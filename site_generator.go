package nb8

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
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
	fsys                  FS
	sitePrefix            string
	site                  Site
	markdown              goldmark.Markdown
	mu                    sync.Mutex
	templateCache         map[string]*template.Template
	templateInProgress    map[string]chan struct{}
	compressGeneratedHTML bool
	// Each post list has its own post
	// category settings: postsPerPage (Number of posts per page), visiblePages (Number of pages displayed)
}

type Site struct {
	Title          string
	Favicon        string
	Lang           string
	PostCategories []string
}

type SiteGeneratorConfig struct {
	FS                    FS
	SitePrefix            string
	Title                 string
	Favicon               string
	Lang                  string
	CodeStyle             string
	CompressGeneratedHTML bool
}

func NewSiteGenerator(config SiteGeneratorConfig) (*SiteGenerator, error) {
	char, size := utf8.DecodeRuneInString(config.Favicon)
	if size == len(config.Favicon) {
		config.Favicon = "data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 10 10%22><text y=%221em%22 font-size=%228%22>" + string(char) + "</text></svg>"
	}
	if config.Title == "" {
		config.Title = "My blog"
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
		fsys:       config.FS,
		sitePrefix: config.SitePrefix,
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
		mu:                    sync.Mutex{},
		templateCache:         make(map[string]*template.Template),
		templateInProgress:    make(map[string]chan struct{}),
		compressGeneratedHTML: config.CompressGeneratedHTML,
	}
	dirEntries, err := siteGen.fsys.ReadDir(path.Join(siteGen.sitePrefix, "posts"))
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
	ext := path.Ext(name)
	pageData := PageData{
		Site:   siteGen.site,
		Parent: path.Dir(name),
		Name:   strings.TrimSuffix(path.Base(name), ext),
	}
	// path.Dir converts empty strings to ".", but we prefer an empty string so
	// convert it back.
	if pageData.Parent == "." {
		pageData.Parent = ""
	}

	// Open the page source file and read its contents.
	file, err := siteGen.fsys.WithContext(ctx).Open(path.Join(siteGen.sitePrefix, "pages", name))
	if err != nil {
		// Special case: fall back to our built-in index.html if the user's
		// index.html doesn't exist. For any other file name, we return the
		// error as usual without falling back.
		if !errors.Is(err, fs.ErrNotExist) && name != "index.html" {
			return err
		}
		file, err = rootFS.Open("static/index.html")
		if err != nil {
			return err
		}
	}
	defer file.Close()
	fileInfo, err := file.Stat()
	if err != nil {
		return err
	}
	if fileInfo.IsDir() {
		return fmt.Errorf("%s is a folder", name)
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
	pageData.UpdatedAt = fileInfo.ModTime()

	// Prepare the page template.
	tmpl, err := siteGen.parseTemplate(ctx, path.Base(name), b.String(), nil)
	if err != nil {
		return err
	}

	// Read the outputDir of the page to get a list of its subdirectories,
	// markdown files and image files.
	var dirNames, markdownNames []string
	parent := path.Join(pageData.Parent, pageData.Name)
	outputDir := path.Join(siteGen.sitePrefix, "output", strings.TrimSuffix(name, ext))
	// TODO: this should be ReadDirFiles instead, and instead of appending to
	// markdownNames we append to markdownEntries []FileDirEntry.
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
				// Wrap the file in a bufio.Reader so we can read the file line
				// by line.
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
				// Reading the file line by line, start writing into the buffer
				// once we find <title> and stop writing once we find </title>.
				buf := bufPool.Get().(*bytes.Buffer)
				buf.Reset()
				defer bufPool.Put(buf)
				var done, found bool
				for !done {
					line, err := reader.ReadSlice('\n')
					if err != nil {
						if err != io.EOF {
							return err
						}
						done = true
					}
					line = bytes.TrimSpace(line)
					if !found {
						i := bytes.Index(line, []byte("<title>"))
						if i > 0 {
							found = true
							// If we find </title> on the same line, we can
							// break immediately.
							j := bytes.Index(line, []byte("</title>"))
							if j > 0 {
								buf.Write(line[i+len("<title>") : j])
								break
							}
							buf.Write(line[i+len("<title>"):])
						}
					} else {
						// Otherwise we keep writing subsequent lines whole
						// until we find </title>.
						i := bytes.Index(line, []byte("</title>"))
						if i > 0 {
							buf.WriteByte(' ')
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
	// have an index.html, resulting in an empty child page. Filter these out.
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
	if !siteGen.compressGeneratedHTML {
		err = tmpl.Execute(writer, &pageData)
		if err != nil {
			return err
		}
	} else {
		gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
		gzipWriter.Reset(writer)
		defer gzipWriterPool.Put(gzipWriter)
		err = tmpl.Execute(gzipWriter, &pageData)
		if err != nil {
			return err
		}
		err = gzipWriter.Close()
		if err != nil {
			return err
		}
	}
	err = writer.Close()
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

func (siteGen *SiteGenerator) GeneratePost(ctx context.Context, name string) error {
	ext := path.Ext(name)
	postData := PostData{
		Site:     siteGen.site,
		Category: path.Dir(name),
		Name:     strings.TrimSuffix(path.Base(name), ext),
	}
	// path.Dir converts empty strings to ".", but we prefer an empty string so
	// convert it back.
	if postData.Category == "." {
		postData.Category = ""
	}
	// Precondition: posts can be nested in at most one directory (the category
	// directory). If the category directory contains any slashes, it consists
	// of more than one directory which means the post is nested too deep.
	if strings.Contains(postData.Category, "/") {
		return fmt.Errorf("%s is not a valid post (too deep inside a directory, maximum 1 level)", name)
	}

	// Open the post template file and read its contents.
	file, err := siteGen.fsys.WithContext(ctx).Open(path.Join(siteGen.sitePrefix, "output/themes/post.html"))
	if err != nil {
		// If the user's post.html doesn't exist, fall back to our built-in
		// post.html.
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		file, err = rootFS.Open("static/post.html")
		if err != nil {
			return err
		}
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

	// Prepare the post template.
	tmpl, err := siteGen.parseTemplate(ctx, "/themes/post.html", b.String(), nil)
	if err != nil {
		return err
	}

	// Get images belonging to the post.
	g, ctx := errgroup.WithContext(ctx)
	parent := path.Join(postData.Category, postData.Name)
	outputDir := path.Join(siteGen.sitePrefix, "output/posts", strings.TrimSuffix(name, ext))
	g.Go(func() error {
		dirEntries, err := siteGen.fsys.WithContext(ctx).ReadDir(outputDir)
		if err != nil {
			return err
		}
		for _, dirEntry := range dirEntries {
			name := dirEntry.Name()
			if dirEntry.IsDir() {
				continue
			}
			fileType := fileTypes[path.Ext(name)]
			if strings.HasPrefix(fileType.ContentType, "image") {
				postData.Images = append(postData.Images, Image{Parent: parent, Name: name})
				continue
			}
		}
		return nil
	})

	// Read the post markdown content and convert it to HTML.
	g.Go(func() error {
		file, err = siteGen.fsys.WithContext(ctx).Open(path.Join(siteGen.sitePrefix, "posts", name))
		if err != nil {
			return err
		}
		defer file.Close()
		fileInfo, err := file.Stat()
		if err != nil {
			return err
		}
		if fileInfo.IsDir() {
			return fmt.Errorf("%s is a folder", name)
		}
		buf := bufPool.Get().(*bytes.Buffer)
		buf.Reset()
		defer bufPool.Put(buf)
		buf.Grow(int(fileInfo.Size()))
		_, err = io.Copy(buf, file)
		if err != nil {
			return err
		}
		err = file.Close()
		if err != nil {
			return err
		}
		// UpdatedAt
		postData.UpdatedAt = fileInfo.ModTime()
		// CreatedAt
		prefix, _, ok := strings.Cut(name, "-")
		if ok && len(prefix) > 0 && len(prefix) <= 8 {
			b, _ := base32Encoding.DecodeString(fmt.Sprintf("%08s", prefix))
			if len(b) == 5 {
				var timestamp [8]byte
				copy(timestamp[len(timestamp)-5:], b)
				postData.CreatedAt = time.Unix(int64(binary.BigEndian.Uint64(timestamp[:])), 0)
			}
		}
		// Title
		var line []byte
		remainder := buf.Bytes()
		for len(remainder) > 0 {
			line, remainder, _ = bytes.Cut(remainder, []byte("\n"))
			line = bytes.TrimSpace(line)
			if len(line) == 0 {
				continue
			}
			postData.Title = stripMarkdownStyles(line)
			break
		}
		// Content
		var b strings.Builder
		err = siteGen.markdown.Convert(buf.Bytes(), &b)
		if err != nil {
			return err
		}
		postData.Content = template.HTML(b.String())
		return nil
	})

	err = g.Wait()
	if err != nil {
		return err
	}

	// Render the template contents into the output index.html.
	writer, err := siteGen.fsys.WithContext(ctx).OpenWriter(path.Join(outputDir, "index.html"), 0644)
	defer writer.Close()
	if !siteGen.compressGeneratedHTML {
		err = tmpl.Execute(writer, &postData)
		if err != nil {
			return err
		}
	} else {
		gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
		gzipWriter.Reset(writer)
		defer gzipWriterPool.Put(gzipWriter)
		err = tmpl.Execute(gzipWriter, &postData)
		if err != nil {
			return err
		}
		err = gzipWriter.Close()
		if err != nil {
			return err
		}
	}
	err = writer.Close()
	if err != nil {
		return err
	}
	return nil
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
	CreatedAt time.Time
	UpdatedAt time.Time
}

type PostListData struct {
	Site       Site
	Category   string
	Pagination Pagination
	PostList   []Post
}

func (siteGen *SiteGenerator) GeneratePostList(ctx context.Context, category string) error {
	postListData := PostListData{
		Site:     siteGen.site,
		Category: category,
	}
	// NOTE: we eventually want some way to paginate
	dirEntries, err := siteGen.fsys.WithContext(ctx).ReadDir(path.Join(siteGen.sitePrefix, "posts", category))
	if err != nil {
		return err
	}
	for _, dirEntry := range dirEntries {
		_ = dirEntry
	}
	_ = postListData
	return nil
}

func (siteGen *SiteGenerator) parseTemplate(ctx context.Context, name, text string, callers []string) (*template.Template, error) {
	currentTemplate, err := template.New(name).Funcs(funcMap).Parse(text)
	if err != nil {
		return nil, TemplateErrors{
			name: {
				err.Error(),
			},
		}
	}
	var errmsgs []string
	internalTemplates := currentTemplate.Templates()
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
				// resulted in errors.
				externalTemplates[i] = cachedTemplate
				return nil
			}

			// We unconditionally put the cachedTemplate pointer into the
			// templateCache first. This is to indicate that we have already
			// seen this template. If parsing succeeds, we simply populate the
			// template pointer (faster than writing to the templateCache map
			// again). If we fail, the cachedTemplate pointer stays nil and
			// should be treated as a signal by other goroutines that parsing
			// this template has errors. Other goroutines are blocked from
			// accessing the cachedTemplate pointer until the wait channel is
			// closed by the defer function below (once this goroutine exits).
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
	var nilTemplateNames []string
	for i, tmpl := range externalTemplates {
		// A nil template means someone else attempted to parse that template
		// but failed (meaning it has errors), which blocks us from
		// successfully parsing the current template. Accumulate all the
		// failing template names and report it to the user.
		if tmpl == nil {
			nilTemplateNames = append(nilTemplateNames, externalNames[i])
		}
	}
	if len(nilTemplateNames) > 0 {
		mergedErrs[name] = append(mergedErrs[name], fmt.Sprintf("the following templates have errors: %s", strings.Join(nilTemplateNames, ", ")))
	}
	if len(mergedErrs) > 0 {
		return nil, TemplateErrors(mergedErrs)
	}

	finalTemplate := template.New(name).Funcs(funcMap)
	for i, tmpl := range externalTemplates {
		for _, tmpl := range tmpl.Templates() {
			_, err = finalTemplate.AddParseTree(tmpl.Name(), tmpl.Tree)
			if err != nil {
				return nil, fmt.Errorf("%s: %s: add %s: %w", name, externalNames[i], tmpl.Name(), err)
			}
		}
	}
	for _, tmpl := range internalTemplates {
		_, err = finalTemplate.AddParseTree(tmpl.Name(), tmpl.Tree)
		if err != nil {
			return nil, fmt.Errorf("%s: add %s: %w", name, tmpl.Name(), err)
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
