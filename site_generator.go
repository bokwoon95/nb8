package nb8

import (
	"context"
	"fmt"
	"html/template"
	"io/fs"
	"path"
	"strings"
	"sync"
	"time"
)

type SiteGenerator struct {
	fsys                 fs.FS
	sitePrefix           string
	site                 Site
	cleanupOrphanedPages bool
	mu                   sync.Mutex
	templates            map[string]*template.Template
	templateErrors       map[string][]string
	templateInProgress   map[string]chan struct{}
}

func NewSiteGenerator(fsys fs.FS, sitePrefix string, cleanupOrphanedPages bool) (*SiteGenerator, error) {
	siteGenerator := &SiteGenerator{
		fsys:                 fsys,
		sitePrefix:           sitePrefix,
		cleanupOrphanedPages: cleanupOrphanedPages,
		mu:                   sync.Mutex{},
		templates:            make(map[string]*template.Template),
		templateErrors:       make(map[string][]string),
		templateInProgress:   make(map[string]chan struct{}),
	}
	// TODO: populate siteGenerator.site
	return siteGenerator, nil
}

// parent=pages&name=index.html&name=abcd.html&cat.html

// {{ template "/themes/word-up.html" }}
// {{ template "/themes/github.com/bokwoon95/plainsimple/very/long/path/to/file.html" }}

// TODO: we need a new structure that encapsulates template errors into an
// error, so that we can return it instead of asking the user to check the
// templateErrors themselves.

func (siteGenerator *SiteGenerator) Generate(ctx context.Context, parent string, names []string) error {
	return siteGenerator.generate(ctx, parent, names, nil)
}

func (siteGenerator *SiteGenerator) generate(ctx context.Context, parent string, names []string, callers []string) error {
	// TODO: each generate() call uses its own errgroup, and each goroutine inside that errgroup may nest another errgroup (and so on and so forth).
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

type Site struct {
	Title          string
	Favicon        string
	Lang           string
	PostCategories []string
}

type Image struct {
	Parent string
	Name   string
}

type Page struct {
	Parent string
	Name   string
	Title  string
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
}

type PostData struct {
	Site      Site
	Category  string
	Name      string
	Title     string
	Content   template.HTML
	CreatedAt time.Time
	UpdatedAt time.Time
	Images    []Image
}

type Pagination struct {
	Numbers []string
	First   string
	Prev    string
	Current string
	Next    string
	Last    string
}

type Post struct {
	Category  string
	Name      string
	Title     string
	Preview   string
	CreatedAt time.Time
	Images    []Image
}

type PostListData struct {
	Site       Site
	Category   string
	Pagination Pagination
	PostList   []Post
}
