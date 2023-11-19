package nb8

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"path"
	"slices"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"golang.org/x/sync/errgroup"
)

type SiteGenerator struct {
	fsys                 FS
	sitePrefix           string
	site                 Site
	cleanupOrphanedPages bool
	mu                   sync.Mutex
	templates            map[string]*template.Template
	templateErrors       map[string][]string
	templateInProgress   map[string]chan struct{}
	cleanupErrors        []string
}

type Site struct {
	Title          string   `json:"title"`
	Favicon        string   `json:"favicon"`
	Lang           string   `json:"lang"`
	PostCategories []string `json:"-"`
}

// site-config.json
// post-config.json

func NewSiteGenerator(fsys FS, sitePrefix string, cleanupOrphanedPages bool) (*SiteGenerator, error) {
	siteGenerator := &SiteGenerator{
		fsys:                 fsys,
		sitePrefix:           sitePrefix,
		cleanupOrphanedPages: cleanupOrphanedPages,
		mu:                   sync.Mutex{},
		templates:            make(map[string]*template.Template),
		templateErrors:       make(map[string][]string),
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
		err := decoder.Decode(&siteGenerator.site)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path.Join(sitePrefix, "site-config.json"), err)
		}
	}
	if siteGenerator.site.Title == "" {
		siteGenerator.site.Title = "My blog"
	}
	if siteGenerator.site.Favicon == "" {
		siteGenerator.site.Favicon = "data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 10 10%22><text y=%221em%22 font-size=%228%22>☕</text></svg>"
	} else {
		char, size := utf8.DecodeRuneInString(siteGenerator.site.Favicon)
		if size == len(siteGenerator.site.Favicon) {
			siteGenerator.site.Favicon = "data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 10 10%22><text y=%221em%22 font-size=%228%22>" + string(char) + "</text></svg>"
		}
	}
	if siteGenerator.site.Lang == "" {
		siteGenerator.site.Lang = "en"
	}
	dirEntries, err := fsys.ReadDir(path.Join(sitePrefix, "posts"))
	if err != nil {
		return nil, err
	}
	for _, dirEntry := range dirEntries {
		if dirEntry.IsDir() {
			siteGenerator.site.PostCategories = append(siteGenerator.site.PostCategories, dirEntry.Name())
		}
	}
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
	var readDir bool
	_ = readDir
	if len(names) == 0 {
		readDir = true
		dirEntries, err := siteGenerator.fsys.ReadDir(path.Join(siteGenerator.sitePrefix, parent))
		if err != nil {
			return err
		}
		for _, dirEntry := range dirEntries {
			names = append(names, dirEntry.Name())
		}
	} else {
		slices.SortFunc(names, func(a, b string) int {
			extA := path.Ext(a)
			extB := path.Ext(b)
			if extA != "" && extB == "" {
				return 1
			}
			if extA == "" && extB != "" {
				return -1
			}
			return strings.Compare(a, b)
		})
	}
	head, _, _ := strings.Cut(parent, "/")
	if head != "pages" && head != "posts" {
		return fmt.Errorf("invalid parent")
	}
	g, ctx := errgroup.WithContext(ctx)
	_ = g
	switch head {
	case "pages":
	case "posts":
	default:
		return fmt.Errorf("invalid parent")
	}
	// TODO: each generate() call uses its own errgroup, and each goroutine inside that errgroup may nest another errgroup (and so on and so forth).
	// TODO: hardcode the postsPerPage as 100 first, later on we can use
	// TODO: note down where is the appropriate point to regenerate the RSS feed: we will fill this in later. Perhaps this
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
