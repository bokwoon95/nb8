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
	"text/template/parse"
	"time"
	"unicode/utf8"

	"golang.org/x/sync/errgroup"
)

type SiteGenerator struct {
	fsys               FS
	sitePrefix         string
	site               Site
	mu                 sync.Mutex
	templates          map[string]*template.Template
	templateErrors     map[string][]string
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
		fsys:                 fsys,
		sitePrefix:           sitePrefix,
		mu:                   sync.Mutex{},
		templates:            make(map[string]*template.Template),
		templateInProgress:   make(map[string]chan struct{}),
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
	return nil
}

func (siteGen *SiteGenerator) getTemplate(ctx context.Context, name string, callers []string) (*template.Template, error) {
	file, err := siteGen.fsys.Open(path.Join(siteGen.sitePrefix, "output", name))
	if err != nil {
		return nil, err
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if fileInfo.IsDir() {
		return nil, fmt.Errorf("%s is not a template", name)
	}
	var b strings.Builder
	b.Grow(int(fileInfo.Size()))
	_, err = io.Copy(&b, file)
	if err != nil {
		return nil, err
	}
	err = file.Close()
	if err != nil {
		return nil, err
	}
	primaryTemplate, err := template.New(name).Funcs(funcMap).Parse(b.String())
	if err != nil {
		return nil, TemplateErrors{name: {err.Error()}}
	}
	primaryTemplates := primaryTemplate.Templates()
	slices.SortFunc(primaryTemplates, func(t1, t2 *template.Template) int {
		return strings.Compare(t1.Name(), t2.Name())
	})
	var errmsgs []string
	for _, tmpl := range primaryTemplates {
		internalName := tmpl.Name()
		if strings.HasSuffix(internalName, ".html") && internalName != name {
			errmsgs = append(errmsgs, fmt.Sprintf("%s: define %q: internal template name cannot end with .html", name, internalName))
		}
	}
	if len(errmsgs) > 0 {
		return nil, TemplateErrors{name: errmsgs}
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
					if strings.HasPrefix(node.Name, "/themes/") {
						names = append(names, node.Name)
					} else {
						errmsgs = append(errmsgs, fmt.Sprintf("%s: template %q: external template name must start with /themes/", name, node.Name))
					}
				}
			}
		}
	}
	if len(errmsgs) > 0 {
		return nil, TemplateErrors{name: errmsgs}
	}
	slices.Sort(names)
	names = slices.Compact(names)
	g, ctx := errgroup.WithContext(ctx)
	templates := make([]*template.Template, len(names))
	errs := make([]error, len(name))
	for i, name := range names {
		i, name := i, name
		g.Go(func() error {
			if slices.Contains(callers, name) {
				errs[i] = fmt.Errorf(
					"calling %s ends in a circular reference: %s",
					callers[0],
					strings.Join(append(callers, name), " => "),
				)
				return nil
			}
			siteGen.mu.Lock()
			wait := siteGen.templateInProgress[name]
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
			tmpl := siteGen.templates[name]
			siteGen.mu.Unlock()
			if tmpl != nil {
				templates[i] = tmpl
				return nil
			}
			wait = make(chan struct{})
			siteGen.mu.Lock()
			siteGen.templateInProgress[name] = wait
			siteGen.mu.Unlock()
			tmpl, err := siteGen.getTemplate(ctx, name, append(callers, name))
			if err != nil {
				errs[i] = err
			}
			siteGen.mu.Lock()
			siteGen.templates[name] = tmpl
			delete(siteGen.templateInProgress, name)
			close(wait)
			siteGen.mu.Unlock()
			return nil
		})
	}
	err = g.Wait()
	if err != nil {
		return nil, err
	}
	errMap := make(map[string][]string)
	for _, err := range errs {
		if err == nil {
			continue
		}
		if templateErrors, ok := err.(TemplateErrors); ok {
			for name, errmsgs := range templateErrors {
				errMap[name] = append(errMap[name], errmsgs...)
			}
			continue
		}
		errMap[name] = append(errMap[name], err.Error())
	}
	if len(errMap) > 0 {
		for name, errmsgs := range errMap {
			slices.Sort(errmsgs)
			errMap[name] = slices.Compact(errmsgs)
		}
		return nil, TemplateErrors(errMap)
	}
	finalTemplate := template.New(name).Funcs(funcMap)
	for i, tmpl := range templates {
		for _, tmpl := range tmpl.Templates() {
			_, err = finalTemplate.AddParseTree(tmpl.Name(), tmpl.Tree)
			if err != nil {
				return nil, fmt.Errorf("%s: %s: add %s: %w", name, names[i], tmpl.Name(), err)
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
	g, ctx := errgroup.WithContext(ctx)
	fsys := siteGen.fsys.WithContext(ctx)
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
