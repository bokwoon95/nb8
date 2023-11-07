package nb8

import (
	"context"
	"encoding/json"
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
	"time"
)

type TemplateParser struct {
	ctx        context.Context
	nbrew      *Notebrew
	sitePrefix string
	siteURL    string
	mu         *sync.RWMutex // protects cache and errmsgs
	cache      map[string]*template.Template
	errmsgs    map[string][]string
	inProgress map[string]chan struct{}
	funcMap    map[string]any
}

// createpost
// updatepost
// deletepost
// createpage
// updatepage
// regenerateSite

func NewTemplateParser(ctx context.Context, nbrew *Notebrew, sitePrefix string) (*TemplateParser, error) {
	siteName := strings.TrimPrefix(sitePrefix, "@")
	adminURL := nbrew.Scheme + nbrew.Domain
	siteURL := nbrew.Scheme + nbrew.ContentDomain
	if strings.Contains(siteName, ".") {
		siteURL = "https://" + siteName
	} else if siteName != "" && nbrew.Multisite {
		siteURL = nbrew.Scheme + siteName + "." + nbrew.ContentDomain
	}
	var shortSiteURL string
	if strings.HasPrefix(siteURL, "https://") {
		shortSiteURL = strings.TrimSuffix(strings.TrimPrefix(siteURL, "https://"), "/")
	} else {
		shortSiteURL = strings.TrimSuffix(strings.TrimPrefix(siteURL, "http://"), "/")
	}
	var categories []string
	var categoriesErr error
	var categoriesOnce sync.Once
	var postsMu sync.RWMutex
	postsCache := make(map[string][]Post)
	parser := &TemplateParser{
		ctx:        ctx,
		nbrew:      nbrew,
		sitePrefix: sitePrefix,
		siteURL:    siteURL,
		mu:         &sync.RWMutex{},
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
			"adminURL":         func() string { return adminURL },
			"siteURL":          func() string { return siteURL },
			"shortSiteURL":     func() string { return shortSiteURL },
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
			"getCategories": func() ([]string, error) {
				categoriesOnce.Do(func() {
					var dirEntries []fs.DirEntry
					dirEntries, categoriesErr = nbrew.FS.ReadDir(path.Join(sitePrefix, "posts"))
					if categoriesErr != nil {
						return
					}
					for _, dirEntry := range dirEntries {
						if !dirEntry.IsDir() {
							continue
						}
						category := dirEntry.Name()
						if category != urlSafe(category) {
							continue
						}
						categories = append(categories, category)
					}
				})
				return categories, categoriesErr
			},
			"getPosts": func(category string) ([]Post, error) {
				postsMu.RLock()
				posts, ok := postsCache[category]
				postsMu.RUnlock()
				if !ok {
					var err error
					posts, err = nbrew.getPosts(ctx, sitePrefix, category)
					if err != nil {
						return nil, err
					}
					postsMu.Lock()
					postsCache[category] = posts
					postsMu.Unlock()
				}
				return posts, nil
			},
		},
	}
	return parser, nil
}

func (parser *TemplateParser) Parse(templateText string) (*template.Template, error) {
	return parser.parse("", templateText, nil)
}

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
		return nil, TemplateError(parser.errmsgs)
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
	parser.mu.RLock()
	errmsgs := parser.errmsgs
	parser.mu.RUnlock()
	if len(errmsgs) > 0 {
		return nil, TemplateError(errmsgs)
	}
	var names []string
	var node parse.Node
	var nodes []parse.Node
	for _, tmpl := range primaryTemplates {
		if tmpl.Tree == nil {
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
			return nil, TemplateError(parser.errmsgs)
		}
		parser.mu.RLock()
		wait := parser.inProgress[name]
		parser.mu.RUnlock()
		if wait != nil {
			select {
			case <-parser.ctx.Done():
				return nil, parser.ctx.Err()
			case <-wait:
				break
			}
		}
		parser.mu.RLock()
		tmpl := parser.cache[name]
		parser.mu.RUnlock()
		if tmpl == nil {
			wait := make(chan struct{})
			parser.mu.Lock()
			parser.inProgress[name] = wait
			parser.mu.Unlock()
			defer func() {
				parser.mu.Lock()
				close(wait)
				delete(parser.inProgress, name)
				parser.mu.Unlock()
			}()
			file, err := parser.nbrew.FS.WithContext(parser.ctx).Open(path.Join(parser.sitePrefix, "output/themes", name))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					parser.mu.Lock()
					parser.errmsgs[name] = append(parser.errmsgs[name], fmt.Sprintf("%s calls nonexistent template %q", templateName, name))
					parser.mu.Unlock()
					continue
				}
				return nil, fmt.Errorf("%s: open %s: %w", templateName, name, err)
			}
			fileinfo, err := file.Stat()
			if err != nil {
				return nil, fmt.Errorf("%s: stat %s: %w", templateName, name, err)
			}
			var b strings.Builder
			b.Grow(int(fileinfo.Size()))
			_, err = io.Copy(&b, file)
			if err != nil {
				return nil, fmt.Errorf("%s: read %s: %w", templateName, name, err)
			}
			err = file.Close()
			if err != nil {
				return nil, fmt.Errorf("%s: close %s: %w", templateName, name, err)
			}
			text := b.String()
			tmpl, err = parser.parse(name, text, append(callers, name))
			if err != nil {
				return nil, err
			}
			if tmpl == nil {
				continue
			}
			parser.mu.Lock()
			parser.cache[name] = tmpl
			parser.mu.Unlock()
		}
		for _, tmpl := range tmpl.Templates() {
			_, err = finalTemplate.AddParseTree(tmpl.Name(), tmpl.Tree)
			if err != nil {
				return nil, fmt.Errorf("%s: %s: add %s: %w", templateName, name, tmpl.Name(), err)
			}
		}
	}
	parser.mu.RLock()
	errmsgs = parser.errmsgs
	parser.mu.RUnlock()
	if len(errmsgs) > 0 {
		return nil, TemplateError(errmsgs)
	}
	for _, tmpl := range primaryTemplates {
		_, err = finalTemplate.AddParseTree(tmpl.Name(), tmpl.Tree)
		if err != nil {
			return nil, fmt.Errorf("%s: add %s: %w", templateName, tmpl.Name(), err)
		}
	}
	return finalTemplate.Lookup(templateName), nil
}

type TemplateError map[string][]string

func (templateErrors TemplateError) Error() string {
	b, _ := json.MarshalIndent(templateErrors, "", "  ")
	return fmt.Sprintf("the following templates have errors: %s", string(b))
}

func (templateErrors TemplateError) Errors() []Error {
	var errmsgs []Error
	names := make([]string, 0, len(templateErrors))
	for name := range templateErrors {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		for _, errmsg := range templateErrors[name] {
			errmsgs = append(errmsgs, Error(errmsg))
		}
	}
	return errmsgs
}

func (nbrew *Notebrew) RegenerateSite(ctx context.Context, sitePrefix string) error {
	return nil
}

type ctxWriter struct {
	ctx  context.Context
	dest io.Writer
}

func (w *ctxWriter) Write(p []byte) (n int, err error) {
	err = w.ctx.Err()
	if err != nil {
		return 0, err
	}
	return w.dest.Write(p)
}

type Post struct {
	URL       string
	Category  string
	Name      string
	Title     string
	Preview   string
	Content   template.HTML
	CreatedAt time.Time
	UpdatedAt time.Time
}

// TODO: getPosts needs a revamp. It now needs to return a struct with the
// total number of pages, the current page number plus the slices of (possibly
// paginated) posts.
func (nbrew *Notebrew) getPosts(ctx context.Context, sitePrefix, category string) ([]Post, error) {
	return nil, nil
}
