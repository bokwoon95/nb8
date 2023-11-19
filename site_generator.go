package nb8

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"path"
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
	char, size := utf8.DecodeRuneInString(siteGenerator.site.Favicon)
	if size == len(siteGenerator.site.Favicon) {
		siteGenerator.site.Favicon = "data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 10 10%22><text y=%221em%22 font-size=%228%22>" + string(char) + "</text></svg>"
	} else {
		siteGenerator.site.Favicon = "data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 10 10%22><text y=%221em%22 font-size=%228%22>☕</text></svg>"
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
	head, _, _ := strings.Cut(parent, "/")
	switch head {
	case "pages":
		var dirNames, fileNames []string
		if len(names) > 0 {
			for _, name := range names {
				fileInfo, err := fs.Stat(siteGenerator.fsys, path.Join(siteGenerator.sitePrefix, parent, name))
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
			dirEntries, err := siteGenerator.fsys.ReadDir(path.Join(siteGenerator.sitePrefix, parent))
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

func (siteGenerator *SiteGenerator) generatePages(ctx context.Context, parent string, dirNames, fileNames []string) error {
	dirGroup, ctx := errgroup.WithContext(ctx)
	for _, dirName := range dirNames {
		newParent := path.Join(parent, dirName)
		dirGroup.Go(func() error {
			dirEntries, err := siteGenerator.fsys.ReadDir(newParent)
			if err != nil {
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
			return siteGenerator.generatePages(ctx, newParent, newDirNames, newFileNames)
		})
	}
	err := dirGroup.Wait()
	if err != nil {
		return err
	}
	// parent=x&name=y
	// fileGroup, ctx := errgroup.WithContext(ctx)
	// for _, fileName := range fileNames {
	// }
	return nil
}

func (siteGenerator *SiteGenerator) parseTemplate(ctx context.Context, name string, callers []string) (*template.Template, error) {
	return nil, nil
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

type TemplateError map[string][]string

func (templateErrors TemplateError) Error() string {
	b, _ := json.MarshalIndent(templateErrors, "", "  ")
	return fmt.Sprintf("the following templates have errors: %s", string(b))
}
