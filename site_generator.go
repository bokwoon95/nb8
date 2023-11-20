package nb8

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/http"
	"path"
	"slices"
	"strings"
	"sync"
	"syscall"
	"text/template/parse"
	"time"
	"unicode/utf8"

	"github.com/yuin/goldmark"
	highlighting "github.com/yuin/goldmark-highlighting"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	goldmarkhtml "github.com/yuin/goldmark/renderer/html"
	"golang.org/x/sync/errgroup"
)

type SiteGenerator struct {
	fsys               FS
	sitePrefix         string
	site               Site
	markdown           goldmark.Markdown
	baseTemplate       *template.Template
	mu                 sync.Mutex
	templateCache      map[string]*template.Template
	templateInProgress map[string]chan struct{}
}

type Site struct {
	Title          string
	Favicon        string
	Lang           string
	PostCategories []string
}

func NewSiteGenerator(fsys FS, sitePrefix string) (*SiteGenerator, error) {
	var config struct {
		Title     string `json:"title"`
		Favicon   string `json:"favicon"`
		Lang      string `json:"lang"`
		CodeStyle string `json:"codeStyle"`
	}
	file, err := fsys.Open(path.Join(sitePrefix, "site-config.json"))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return nil, err
		}
	} else {
		decoder := json.NewDecoder(file)
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&config)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path.Join(sitePrefix, "site-config.json"), err)
		}
	}
	char, size := utf8.DecodeRuneInString(config.Favicon)
	if size == len(config.Favicon) {
		config.Favicon = "data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 10 10%22><text y=%221em%22 font-size=%228%22>" + string(char) + "</text></svg>"
	}
	if config.Favicon == "" {
		config.Favicon = "data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 10 10%22><text y=%221em%22 font-size=%228%22>☕</text></svg>"
	}
	if config.Lang == "" {
		config.Lang = "en"
	}
	if config.CodeStyle == "" {
		config.CodeStyle = "dracula"
	}
	siteGen := &SiteGenerator{
		fsys:       fsys,
		sitePrefix: sitePrefix,
		site: Site{
			Title:   config.Title,
			Favicon: config.Favicon,
			Lang:    config.Lang,
		},
		markdown: goldmark.New(
			goldmark.WithParserOptions(parser.WithAttribute()),
			goldmark.WithExtensions(
				extension.Table,
				highlighting.NewHighlighting(highlighting.WithStyle(config.CodeStyle)),
			),
			goldmark.WithRendererOptions(goldmarkhtml.WithUnsafe()),
		),
		baseTemplate:       template.New("").Funcs(funcMap),
		mu:                 sync.Mutex{},
		templateCache:      make(map[string]*template.Template),
		templateInProgress: make(map[string]chan struct{}),
	}
	if siteGen.site.Title == "" {
		siteGen.site.Title = "My blog"
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

type Page struct {
	Parent string
	Name   string
	Title  string
}

type Image struct {
	Parent string
	Name   string
}

type PageData struct {
	Site       Site
	Parent     string
	Name       string
	ChildPages []Page
	Markdown   map[string]template.HTML
	Images     []Image
	UpdatedAt  time.Time
}

func (siteGen *SiteGenerator) GeneratePage(ctx context.Context, name string) error {
	// Open the page source file and read its contents.
	file, err := siteGen.fsys.WithContext(ctx).Open(path.Join(siteGen.sitePrefix, "pages", name))
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
	err = file.Close()
	if err != nil {
		return err
	}

	// Prepare the page template.
	tmpl, err := siteGen.parseTemplate(ctx, name, b.String(), nil)
	if err != nil {
		return err
	}

	// Prepare the page data.
	ext := path.Ext(name)
	pageData := PageData{
		Site:      siteGen.site,
		Parent:    path.Dir(name),
		Name:      strings.TrimSuffix(path.Base(name), ext),
		UpdatedAt: fileInfo.ModTime(),
	}

	// Read the outputDir of the page to get a list of its subdirectories,
	// markdown files and image files.
	var dirNames, markdownNames []string
	parent := path.Join(pageData.Parent, pageData.Name)
	outputDir := path.Join(siteGen.sitePrefix, "output", strings.TrimSuffix(name, ext))
	dirEntries, err := siteGen.fsys.WithContext(ctx).ReadDir(outputDir)
	if err != nil {
		return err
	}
	for _, dirEntry := range dirEntries {
		name := dirEntry.Name()
		if dirEntry.IsDir() {
			dirNames = append(dirNames, name)
			continue
		}
		fileType := fileTypes[path.Ext(name)]
		if strings.HasPrefix(fileType.ContentType, "text/markdown") {
			markdownNames = append(markdownNames, name)
			continue
		}
		if strings.HasPrefix(fileType.ContentType, "image") {
			pageData.Images = append(pageData.Images, Image{Parent: parent, Name: name})
			continue
		}
	}

	// For each markdown file, read its contents, convert to HTML and populate
	// the pageData.Markdown map.
	g, ctx := errgroup.WithContext(ctx)
	var markdownMu sync.Mutex
	g.Go(func() error {
		g, ctx := errgroup.WithContext(ctx)
		for _, markdownName := range markdownNames {
			markdownName := markdownName
			g.Go(func() error {
				file, err := siteGen.fsys.WithContext(ctx).Open(path.Join(outputDir, markdownName))
				if err != nil {
					return err
				}
				defer file.Close()
				buf := bufPool.Get().(*bytes.Buffer)
				buf.Reset()
				defer bufPool.Put(buf)
				_, err = buf.ReadFrom(file)
				if err != nil {
					return err
				}
				var b strings.Builder
				err = siteGen.markdown.Convert(buf.Bytes(), &b)
				if err != nil {
					return err
				}
				markdownMu.Lock()
				pageData.Markdown[markdownName] = template.HTML(b.String())
				markdownMu.Unlock()
				return nil
			})
		}
		return g.Wait()
	})

	// For each subdirectory in the outputDir, check if it has a child page
	// (contains index.html) and get its title.
	pageData.ChildPages = make([]Page, len(dirNames))
	g.Go(func() error {
		g, ctx := errgroup.WithContext(ctx)
		for i, dirName := range dirNames {
			i, dirName := i, dirName
			g.Go(func() error {
				file, err := siteGen.fsys.WithContext(ctx).Open(path.Join(outputDir, dirName, "index.html"))
				if err != nil {
					if errors.Is(err, fs.ErrNotExist) {
						return nil
					}
					return err
				}
				defer file.Close()
				reader := readerPool.Get().(*bufio.Reader)
				reader.Reset(file)
				defer readerPool.Put(reader)
				// Peek the first 512 bytes of index.html to detect if it is
				// gzipped. If so, wrap the reader in a gzip.Reader followed by
				// another bufio.Reader (so that we retain the ability to read
				// the file line by line).
				b, err := reader.Peek(512)
				if err != nil && err != io.EOF {
					return err
				}
				contentType := http.DetectContentType(b)
				if contentType == "application/x-gzip" || contentType == "application/gzip" {
					gzipReader := gzipReaderPool.Get().(*gzip.Reader)
					if gzipReader != nil {
						err = gzipReader.Reset(reader)
						if err != nil {
							return err
						}
					} else {
						gzipReader, err = gzip.NewReader(reader)
						if err != nil {
							return err
						}
					}
					defer gzipReaderPool.Put(gzipReader)
					newReader := readerPool.Get().(*bufio.Reader)
					newReader.Reset(gzipReader)
					defer readerPool.Put(newReader)
					reader = newReader
				}
				buf := bufPool.Get().(*bytes.Buffer)
				buf.Reset()
				defer bufPool.Put(buf)
				next, found := true, false
				for next {
					line, err := reader.ReadSlice('\n')
					if err != nil {
						if err != io.EOF {
							return err
						}
						next = false
					}
					line = bytes.TrimSpace(line)
					if !found {
						i := bytes.Index(line, []byte("<title>"))
						if i > 0 {
							found = true
							j := bytes.Index(line, []byte("</title>"))
							if j > 0 {
								buf.Write(line[i+len("<title>") : j])
								break
							}
							buf.Write(line[i+len("<title>"):])
						}
					} else {
						i := bytes.Index(line, []byte("</title>"))
						if i > 0 {
							buf.Write(line[:i])
							break
						}
						buf.WriteByte(' ')
						buf.Write(line)
					}
				}
				pageData.ChildPages[i] = Page{
					Parent: parent,
					Name:   dirName,
					Title:  buf.String(),
				}
				return nil
			})
		}
		return g.Wait()
	})

	err = g.Wait()
	if err != nil {
		return err
	}

	// It is possible that some of the subdirectories of the outputDir don't
	// have an index.html, resulting in an empty childPage. Filter these out.
	n := 0
	for _, page := range pageData.ChildPages {
		if page == (Page{}) {
			continue
		}
		pageData.ChildPages[n] = page
		n++
	}
	pageData.ChildPages = pageData.ChildPages[:n]

	// Render the template contents into the output index.html.
	writer, err := siteGen.fsys.WithContext(ctx).OpenWriter(path.Join(outputDir, "index.html"), 0644)
	if err != nil {
		return err
	}
	defer writer.Close()
	err = tmpl.Execute(writer, &pageData)
	if err != nil {
		return err
	}
	return nil
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

func (siteGen *SiteGenerator) parseTemplate(ctx context.Context, name, text string, callers []string) (*template.Template, error) {
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

	// Get the list of external templates referenced by the current template.
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
	// sort | uniq deduplication.
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

			file, err := siteGen.fsys.WithContext(ctx).Open(path.Join(siteGen.sitePrefix, "output", externalName))
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

type TemplateErrors map[string][]string

func (e TemplateErrors) Error() string {
	b, _ := json.MarshalIndent(e, "", "  ")
	return fmt.Sprintf("the following templates have errors: %s", string(b))
}
