package nb8

import (
	"context"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/url"
	"path"
	"slices"
	"strings"
	"sync"
	"text/template/parse"
)

type TemplateParser struct {
	ctx        context.Context
	nbrew      *Notebrew
	sitePrefix string
	siteURL    string
	mu         *sync.Mutex
	cache      map[string]*template.Template
	errmsgs    map[string][]string
	inProgress map[string]chan struct{}
	funcMap    map[string]any
}

func NewTemplateParser(ctx context.Context, nbrew *Notebrew, sitePrefix string) (*TemplateParser, error) {
	parser := &TemplateParser{
		ctx:        ctx,
		nbrew:      nbrew,
		sitePrefix: sitePrefix,
		mu:         &sync.Mutex{},
		cache:      make(map[string]*template.Template),
		errmsgs:    make(url.Values),
		inProgress: make(map[string]chan struct{}),
		funcMap: map[string]any{
			"join":             path.Join,
			"base":             path.Base,
			"ext":              path.Ext,
			"trimPrefix":       strings.TrimPrefix,
			"trimSuffix":       strings.TrimSuffix,
			"fileSizeToString": fileSizeToString,
			"safeHTML":         func(s string) template.HTML { return template.HTML(s) },
			"head": func(s string) string {
				head, _, _ := strings.Cut(s, "/")
				return head
			},
			"tail": func(s string) string {
				_, tail, _ := strings.Cut(s, "/")
				return tail
			},
			"list": func(v ...any) []any { return v },
			"dict": func(v ...any) (map[string]any, error) {
				dict := make(map[string]any)
				if len(dict)%2 != 0 {
					return nil, fmt.Errorf("odd number of arguments passed in")
				}
				for i := 0; i+1 < len(dict); i += 2 {
					key, ok := v[i].(string)
					if !ok {
						return nil, fmt.Errorf("value %d (%#v) is not a string", i, v[i])
					}
					value := v[i+1]
					dict[key] = value
				}
				return dict, nil
			},
			"dump": func(a ...any) template.HTML {
				// TODO: convert each argument into json and print each
				// argument out in a <pre style="white-space: pre-wrap"></pre>
				// tag.
				return ""
			},
		},
	}
	return parser, nil
}

// TODO: remove this now that we have a global addressing system, we can
// always use names like "abcd.html" because it' won't clash with
// "/themes/abcd.html".
func (parser *TemplateParser) Parse(templateName string, templateText string) (*template.Template, error) {
	return parser.parse(templateName, templateText, nil)
}

// TODO: oof we may need to do away with this altogether, and only support
// regenerating an entire file or directory at any one time.
func (parser *TemplateParser) parse(templateName, templateText string, callers []string) (*template.Template, error) {
	primaryTemplate, err := template.New(templateName).Funcs(parser.funcMap).Parse(templateText)
	if err != nil {
		parser.mu.Lock()
		// TODO: collect all possible error strings then use string
		// manipulation to format the errmsg into something the user can
		// understand. E.g. if the template name is an empty string, how to
		// make the error more obvious?
		parser.errmsgs[templateName] = append(parser.errmsgs[templateName], strings.TrimSpace(strings.TrimPrefix(err.Error(), "template:")))
		parser.mu.Unlock()
		return nil, TemplateErrors(parser.errmsgs)
	}
	primaryTemplates := primaryTemplate.Templates()
	slices.SortFunc(primaryTemplates, func(t1, t2 *template.Template) int {
		return strings.Compare(t1.Name(), t2.Name())
	})
	for _, tmpl := range primaryTemplates {
		name := tmpl.Name()
		if name != templateName && strings.HasSuffix(name, ".html") {
			parser.mu.Lock()
			parser.errmsgs[templateName] = append(parser.errmsgs[templateName], fmt.Sprintf("%s: define %q: defined template's name cannot end in .html", templateName, name))
			parser.mu.Unlock()
		}
	}
	parser.mu.Lock()
	errmsgs := parser.errmsgs
	parser.mu.Unlock()
	if len(errmsgs) > 0 {
		return nil, TemplateErrors(errmsgs)
	}
	var names []string
	var node parse.Node
	var nodes []parse.Node
	for _, tmpl := range primaryTemplates {
		if tmpl.Tree == nil || tmpl.Tree.Root == nil {
			continue
		}
		nodes = append(nodes, tmpl.Tree.Root.Nodes...)
		for len(nodes) > 0 {
			node, nodes = nodes[len(nodes)-1], nodes[:len(nodes)-1]
			switch node := node.(type) {
			case *parse.ListNode:
				if node == nil {
					continue
				}
				nodes = append(nodes, node.Nodes...)
			case *parse.BranchNode:
				nodes = append(nodes, node.List, node.ElseList)
			case *parse.RangeNode:
				nodes = append(nodes, node.List, node.ElseList)
			case *parse.TemplateNode:
				if strings.HasSuffix(node.Name, ".html") {
					names = append(names, node.Name)
				}
			}
		}
	}
	finalTemplate := template.New(templateName).Funcs(parser.funcMap)
	slices.SortFunc(names, func(name1, name2 string) int {
		return -strings.Compare(name1, name2)
	})
	names = slices.Compact(names)
	for _, name := range names {
		if slices.Contains(callers, name) {
			parser.mu.Lock()
			parser.errmsgs[callers[0]] = append(parser.errmsgs[callers[0]], fmt.Sprintf(
				"calling %s ends in a circular reference: %s",
				callers[0],
				strings.Join(append(callers, name), " => "),
			))
			parser.mu.Unlock()
			return nil, TemplateErrors(parser.errmsgs)
		}
		parser.mu.Lock()
		wait := parser.inProgress[name]
		parser.mu.Unlock()
		if wait != nil {
			select {
			case <-parser.ctx.Done():
				return nil, parser.ctx.Err()
			case <-wait:
				break
			}
		}
		parser.mu.Lock()
		tmpl := parser.cache[name]
		parser.mu.Unlock()
		if tmpl == nil {
			wait := make(chan struct{})
			parser.mu.Lock()
			parser.inProgress[name] = wait
			parser.mu.Unlock()
			file, err := parser.nbrew.FS.WithContext(parser.ctx).Open(path.Join(parser.sitePrefix, "output/themes", name))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					parser.mu.Lock()
					parser.errmsgs[name] = append(parser.errmsgs[name], fmt.Sprintf("%s calls nonexistent template %q", templateName, name))
					parser.mu.Unlock()
					// Need to close(wait) here? God this is so buggy.
					continue
				}
				close(wait)
				return nil, fmt.Errorf("%s: open %s: %w", templateName, name, err)
			}
			fileinfo, err := file.Stat()
			if err != nil {
				close(wait)
				return nil, fmt.Errorf("%s: stat %s: %w", templateName, name, err)
			}
			var b strings.Builder
			b.Grow(int(fileinfo.Size()))
			_, err = io.Copy(&b, file)
			if err != nil {
				close(wait)
				return nil, fmt.Errorf("%s: read %s: %w", templateName, name, err)
			}
			err = file.Close()
			if err != nil {
				close(wait)
				return nil, fmt.Errorf("%s: close %s: %w", templateName, name, err)
			}
			text := b.String()
			tmpl, err = parser.parse(name, text, append(callers, name))
			if err != nil {
				close(wait)
				return nil, err
			}
			// WTF is going on here? Why would tmpl be nil, and why continue?
			if tmpl == nil {
				continue
			}
			parser.mu.Lock()
			parser.cache[name] = tmpl
			close(wait)
			delete(parser.inProgress, name)
			parser.mu.Unlock()
		}
		for _, tmpl := range tmpl.Templates() {
			_, err = finalTemplate.AddParseTree(tmpl.Name(), tmpl.Tree)
			if err != nil {
				return nil, fmt.Errorf("%s: %s: add %s: %w", templateName, name, tmpl.Name(), err)
			}
		}
	}
	parser.mu.Lock()
	errmsgs = parser.errmsgs
	parser.mu.Unlock()
	if len(errmsgs) > 0 {
		return nil, TemplateErrors(errmsgs)
	}
	for _, tmpl := range primaryTemplates {
		_, err = finalTemplate.AddParseTree(tmpl.Name(), tmpl.Tree)
		if err != nil {
			return nil, fmt.Errorf("%s: add %s: %w", templateName, tmpl.Name(), err)
		}
	}
	return finalTemplate.Lookup(templateName), nil
}

func (nbrew *Notebrew) Regenerate(ctx context.Context, sitePrefix string, dir string, names ...string) error {
	return nil
}
