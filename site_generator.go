package nb8

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"path"
	"slices"
	"strings"
	"sync"
	"syscall"
	"text/template/parse"
	"time"
	"unicode/utf8"

	"golang.org/x/sync/errgroup"
)

type SiteGenerator struct {
	fsys               FS
	sitePrefix         string
	site               Site
	baseTemplate       *template.Template
	mu                 sync.Mutex
	templateCache      map[string]*template.Template
	templateInProgress map[string]chan struct{}
}

type Site struct {
	Title          string   `json:"title"`
	Favicon        string   `json:"favicon"`
	Lang           string   `json:"lang"`
	PostCategories []string `json:"-"`
}

func NewSiteGenerator(fsys FS, sitePrefix string) (*SiteGenerator, error) {
	siteGen := &SiteGenerator{
		fsys:               fsys,
		sitePrefix:         sitePrefix,
		baseTemplate:       template.New("").Funcs(funcMap),
		mu:                 sync.Mutex{},
		templateCache:      make(map[string]*template.Template),
		templateInProgress: make(map[string]chan struct{}),
	}
	file, err := fsys.Open(path.Join(sitePrefix, "site-config.json"))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	} else {
		decoder := json.NewDecoder(file)
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&siteGen.site)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path.Join(sitePrefix, "site-config.json"), err)
		}
	}
	if siteGen.site.Title == "" {
		siteGen.site.Title = "My blog"
	}
	char, size := utf8.DecodeRuneInString(siteGen.site.Favicon)
	if size == len(siteGen.site.Favicon) {
		siteGen.site.Favicon = "data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 10 10%22><text y=%221em%22 font-size=%228%22>" + string(char) + "</text></svg>"
	}
	if siteGen.site.Favicon == "" {
		siteGen.site.Favicon = "data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 10 10%22><text y=%221em%22 font-size=%228%22>☕</text></svg>"
	}
	if siteGen.site.Lang == "" {
		siteGen.site.Lang = "en"
	}
	dirEntries, err := fsys.ReadDir(path.Join(sitePrefix, "posts"))
	if err != nil {
		return nil, err
	}
	for _, dirEntry := range dirEntries {
		if dirEntry.IsDir() {
			siteGen.site.PostCategories = append(siteGen.site.PostCategories, dirEntry.Name())
		}
	}
	return siteGen, nil
}

// parent=pages&name=index.html&name=abcd.html&cat.html

// {{ template "/themes/word-up.html" }}
// {{ template "/themes/github.com/bokwoon95/plainsimple/very/long/path/to/file.html" }}

// TODO: we need a new structure that encapsulates template errors into an
// error, so that we can return it instead of asking the user to check the
// templateErrors themselves.

func (siteGen *SiteGenerator) GeneratePage(ctx context.Context, name string) error {
	fsys := siteGen.fsys.WithContext(ctx)
	file, err := fsys.Open(path.Join(siteGen.sitePrefix, "pages", name))
	if err != nil {
		return err
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}
	if fileInfo.IsDir() {
		return fmt.Errorf("%s is not a template", name)
	}
	var b strings.Builder
	b.Grow(int(fileInfo.Size()))
	_, err = io.Copy(&b, file)
	if err != nil {
		return err
	}
	text := b.String()
	err = file.Close()
	if err != nil {
		return err
	}
	tmpl, err := siteGen.parseTemplate(ctx, name, text, nil)
	_ = tmpl
	// read the page contents, parse the page contents, walk the tree looking
	// for external templates, use an errgroup to get all these templates
	// concurrently then merge them again using the same logic. Good god I'm
	// basically duplicating almost everything that getTemplate does :/.
	//
	// maybe getTemplate gets a template text instead, like how it used to be...
	return nil
}

func (siteGen *SiteGenerator) parseTemplate(ctx context.Context, name, text string, callers []string) (*template.Template, error) {
	fsys := siteGen.fsys.WithContext(ctx)
	tmpl, err := siteGen.baseTemplate.Clone()
	if err != nil {
		return nil, err
	}
	tmpl, err = tmpl.New(name).Parse(text)
	if err != nil {
		return nil, TemplateErrors{
			name: {
				err.Error(),
			},
		}
	}
	var errmsgs []string
	internalTemplates := tmpl.Templates()
	for _, tmpl := range internalTemplates {
		internalName := tmpl.Name()
		if strings.HasSuffix(internalName, ".html") && internalName != name {
			errmsgs = append(errmsgs, fmt.Sprintf("%s: define %q: internal template name cannot end with .html", name, internalName))
		}
	}
	if len(errmsgs) > 0 {
		return nil, TemplateErrors{
			name: errmsgs,
		}
	}

	var externalNames []string
	var node parse.Node
	var nodes []parse.Node
	for _, tmpl := range internalTemplates {
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
					if !strings.HasPrefix(node.Name, "/themes/") {
						errmsgs = append(errmsgs, fmt.Sprintf("%s: template %q: external template name must start with /themes/", name, node.Name))
						continue
					}
					externalNames = append(externalNames, node.Name)
				}
			}
		}
	}
	if len(errmsgs) > 0 {
		return nil, TemplateErrors{
			name: errmsgs,
		}
	}

	slices.Sort(externalNames)
	externalNames = slices.Compact(externalNames)
	g, ctx := errgroup.WithContext(ctx)
	externalTemplates := make([]*template.Template, len(externalNames))
	externalTemplateErrs := make([]error, len(externalNames))
	for i, externalName := range externalNames {
		i, externalName := i, externalName
		g.Go(func() error {
			n := slices.Index(callers, externalName)
			if n > 0 {
				externalTemplateErrs[i] = fmt.Errorf("%s has a circular reference: %s", externalName, strings.Join(callers[n:], "=>")+" => "+externalName)
				return nil
			}

			// If a template is currently being parsed, wait for it to finish
			// before checking the templateCache for the result.
			siteGen.mu.Lock()
			wait := siteGen.templateInProgress[externalName]
			siteGen.mu.Unlock()
			if wait != nil {
				select {
				case <-ctx.Done():
					return ctx.Err()
				case <-wait:
					break
				}
			}
			siteGen.mu.Lock()
			cachedTemplate, ok := siteGen.templateCache[externalName]
			siteGen.mu.Unlock()
			if ok {
				// We found the template; add it to the slice and exit. The
				// cachedTemplate may be nil, if parsing that template had
				// errors.
				externalTemplates[i] = cachedTemplate
				return nil
			}

			// We unconditionally put the cachedTemplate pointer into the
			// templateCache first. This is to indicate that we have already
			// seen this template. If parsing succeeds, we simply populate the
			// template pointer (bypassing the need to write to the
			// templateCache again). If we fail, the cachedTemplate pointer
			// stays nil and should be treated as a signal by other goroutines
			// that this parsing this template has errors. Other goroutines are
			// blocked from accessing the cachedTemplate pointer until the wait
			// channel is closed by the defer function below (once this
			// goroutine exits).
			wait = make(chan struct{})
			siteGen.mu.Lock()
			siteGen.templateInProgress[externalName] = wait
			siteGen.templateCache[externalName] = cachedTemplate
			siteGen.mu.Unlock()
			defer func() {
				siteGen.mu.Lock()
				delete(siteGen.templateInProgress, externalName)
				close(wait)
				siteGen.mu.Unlock()
			}()

			file, err := fsys.Open(path.Join(siteGen.sitePrefix, "output", externalName))
			if err != nil {
				// If we cannot find the referenced template, it is not the
				// external template's fault but rather the current template's
				// fault for referencing a non-existent external template.
				// Therefore we return the error (associating it with the
				// current template) instead of adding it to the
				// externalTemplateErrs list.
				if errors.Is(err, fs.ErrNotExist) {
					return &fs.PathError{Op: "parsetemplate", Path: externalName, Err: fs.ErrNotExist}
				}
				externalTemplateErrs[i] = err
				return nil
			}
			defer file.Close()
			fileInfo, err := file.Stat()
			if err != nil {
				externalTemplateErrs[i] = err
				return nil
			}
			if fileInfo.IsDir() {
				// If the referenced template is not a file but a directory, it
				// is the current template's fault for referencing a directory
				// instead of a file. Therefore we return the error
				// (associating it with the current template) instead of adding
				// it to the externalTemplateErrs list.
				return &fs.PathError{Op: "parsetemplate", Path: externalName, Err: syscall.EISDIR}
			}
			var b strings.Builder
			b.Grow(int(fileInfo.Size()))
			_, err = io.Copy(&b, file)
			if err != nil {
				externalTemplateErrs[i] = err
				return nil
			}
			err = file.Close()
			if err != nil {
				externalTemplateErrs[i] = err
				return nil
			}
			externalTemplate, err := siteGen.parseTemplate(ctx, externalName, b.String(), append(slices.Clone(callers), externalName))
			if err != nil {
				externalTemplateErrs[i] = err
				return nil
			}
			externalTemplates[i] = externalTemplate
			*cachedTemplate = *externalTemplate
			return nil
		})
	}
	err = g.Wait()
	if err != nil {
		return nil, TemplateErrors{
			name: {
				err.Error(),
			},
		}
	}

	mergedErrs := make(map[string][]string)
	for i, err := range externalTemplateErrs {
		switch err := err.(type) {
		case nil:
			continue
		case TemplateErrors:
			for externalName, errmsgs := range err {
				mergedErrs[externalName] = append(mergedErrs[externalName], errmsgs...)
			}
		default:
			externalName := externalNames[i]
			mergedErrs[externalName] = append(mergedErrs[externalName], err.Error())
		}
	}
	if len(mergedErrs) > 0 {
		return nil, TemplateErrors(mergedErrs)
	}

	var nilTemplates []string
	for i, tmpl := range externalTemplates {
		if tmpl == nil {
			nilTemplates = append(nilTemplates, externalNames[i])
		}
	}
	if len(nilTemplates) > 0 {
		return nil, TemplateErrors{
			name: {
				fmt.Sprintf("the following templates have errors: %s", strings.Join(nilTemplates, ", ")),
			},
		}
	}

	finalTemplate, err := siteGen.baseTemplate.Clone()
	if err != nil {
		return nil, err
	}
	for i, tmpl := range externalTemplates {
		for _, tmpl := range tmpl.Templates() {
			_, err = finalTemplate.AddParseTree(tmpl.Name(), tmpl.Tree)
			if err != nil {
				return nil, fmt.Errorf("%s: %s: add %s: %w", name, externalNames[i], tmpl.Name(), err)
			}
		}
	}
	for _, tmpl := range internalTemplates {
		for _, tmpl := range tmpl.Templates() {
			_, err = finalTemplate.AddParseTree(tmpl.Name(), tmpl.Tree)
			if err != nil {
				return nil, fmt.Errorf("%s: add %s: %w", name, tmpl.Name(), err)
			}
		}
	}
	return finalTemplate.Lookup(name), nil
}

func (siteGen *SiteGenerator) Generate(ctx context.Context, parent string, names []string) error {
	fsys := siteGen.fsys.WithContext(ctx)
	head, _, _ := strings.Cut(parent, "/")
	switch head {
	case "pages":
		var dirNames, fileNames []string
		if len(names) > 0 {
			for _, name := range names {
				fileInfo, err := fs.Stat(fsys, path.Join(siteGen.sitePrefix, parent, name))
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						continue
					}
					return err
				}
				if fileInfo.IsDir() {
					dirNames = append(dirNames, name)
				} else if path.Ext(name) == ".html" {
					fileNames = append(fileNames, name)
				}
			}
		} else {
			dirEntries, err := fsys.ReadDir(path.Join(siteGen.sitePrefix, parent))
			if err != nil {
				return err
			}
			for _, dirEntry := range dirEntries {
				name := dirEntry.Name()
				if dirEntry.IsDir() {
					dirNames = append(dirNames, name)
				} else if path.Ext(name) == ".html" {
					fileNames = append(fileNames, name)
				}
			}
		}
		return nil
	case "posts":
		return nil
	default:
		return fmt.Errorf("invalid parent")
	}
}

// TODO: each generate() call uses its own errgroup, and each goroutine inside that errgroup may nest another errgroup (and so on and so forth).
// TODO: hardcode the postsPerPage as 100 first, later on we can use
// TODO: note down where is the appropriate point to regenerate the RSS feed: we will fill this in later. Perhaps this
// - If head is "pages", generate all directories first before moving on to files (use separate errgroups for directories and for files).
//     - Generating the directories should store all its results in a map[string][]Page, which can be reused by the corresponding pages to avoid re-reading the same page twice later on when generating the parent page. If we didn't comb the directory and we're generating the parent page, we can just call ReadDir on the directory and peek each file's contents to extract the info.
//     - The map[string][]Page scope only lasts within the method call, so it will be garbage collected once it exits.
//     - If cleanupOrphanedPages is true and we called ReadDir earlier, note down all the pages that we did generate and remove any orphaned pages that are still hanging around in the output folder (use RemoveAll on the entire directory).
// - If the head is "posts",
//     - (sanity check) If we are nested more than one level of folders, return.
//     - If we called ReadDir earlier, for every post we generate we append it to a []Post. Once all posts have been generated we have to regenerate the post list page using that list of posts.
//     - If cleanupOrphanedPages is true and we called ReadDir earlier, note down all the posts that we did generate and remove any orphaned posts that are still hanging around in the output folder (use RemoveAll on the entire directory).

// generatePages doesn't have to return a pages

type Page struct {
	Parent    string
	Name      string
	Title     string
	Images    []Image
	UpdatedAt time.Time
}

type PageData struct {
	Site       Site
	Parent     string
	Name       string
	Title      string
	ChildPages []Page
	NextPage   Page
	PrevPage   Page
	Markdown   map[string]template.HTML
	Images     []Image
	UpdatedAt  time.Time
}

func (siteGen *SiteGenerator) generatePages(ctx context.Context, parent string, dirNames, fileNames []string) error {
	fsys := siteGen.fsys.WithContext(ctx)
	g, ctx := errgroup.WithContext(ctx)
	for _, dirName := range dirNames {
		newParent := path.Join(parent, dirName)
		g.Go(func() error {
			dirEntries, err := fsys.ReadDir(newParent)
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			var newDirNames, newFileNames []string
			for _, dirEntry := range dirEntries {
				name := dirEntry.Name()
				if dirEntry.IsDir() {
					newDirNames = append(newDirNames, name)
				} else if path.Ext(name) == ".html" {
					newFileNames = append(newFileNames, name)
				}
			}
			return siteGen.generatePages(ctx, newParent, newDirNames, newFileNames)
		})
	}
	err := g.Wait()
	if err != nil {
		return err
	}
	// generate page children: parent=x&name=y
	// generate page: parent=x&name=y.html
	// generate ?: parent=x
	// generate post: parent=x&name=y.md
	// generate post list: parent=x
	g, ctx = errgroup.WithContext(ctx)
	for _, fileName := range fileNames {
		fileName := fileName
		g.Go(func() error {
			file, err := fsys.Open(path.Join(parent, fileName))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					return nil
				}
				return err
			}
			fileInfo, err := file.Stat()
			if err != nil {
				return err
			}
			var b strings.Builder
			b.Grow(int(fileInfo.Size()))
			_, err = io.Copy(&b, file)
			if err != nil {
				return err
			}
			return nil
		})
	}
	return nil
}

var funcMap = map[string]any{
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
}

type Image struct {
	Parent string
	Name   string
}

type PostData struct {
	Site      Site
	Category  string
	Name      string
	Title     string
	Content   template.HTML
	Images    []Image
	CreatedAt time.Time
	UpdatedAt time.Time
}

type Pagination struct {
	First   string
	Numbers []string
	Current string
	Last    string
}

type Post struct {
	Category  string
	Name      string
	Title     string
	Preview   string
	Content   template.HTML
	Images    []Image
	CreatedAt time.Time
	UpdatedAt time.Time
}

type PostListData struct {
	Site       Site
	Category   string
	Pagination Pagination
	PostList   []Post
}

type TemplateErrors map[string][]string

func (e TemplateErrors) Error() string {
	b, _ := json.MarshalIndent(e, "", "  ")
	return fmt.Sprintf("the following templates have errors: %s", string(b))
}
