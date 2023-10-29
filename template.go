package nb8

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"net/url"
	"path"
	"runtime"
	"slices"
	"strings"
	"sync"
	"text/template/parse"
	"time"

	"golang.org/x/sync/errgroup"
)

type TemplateParser struct {
	ctx        context.Context
	nbrew      *Notebrew
	sitePrefix string
	siteURL    string
	mu         *sync.RWMutex // protects cache and errmsgs
	cache      map[string]*template.Template
	errmsgs    map[string][]string
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
	adminURL := nbrew.Scheme + nbrew.AdminDomain
	siteURL := nbrew.Scheme + nbrew.ContentDomain
	if strings.Contains(siteName, ".") {
		siteURL = "https://" + siteName
	} else if siteName != "" {
		switch nbrew.MultisiteMode {
		case "subdomain":
			siteURL = nbrew.Scheme + siteName + "." + nbrew.ContentDomain
		case "subdirectory":
			siteURL = nbrew.Scheme + nbrew.ContentDomain + "/" + sitePrefix + "/"
		}
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
		err := parser.ctx.Err()
		if err != nil {
			return nil, err
		}
		parser.mu.RLock()
		tmpl := parser.cache[name]
		parser.mu.RUnlock()
		if tmpl == nil {
			file, err := parser.nbrew.FS.Open(path.Join(parser.sitePrefix, "output/themes", name))
			if errors.Is(err, fs.ErrNotExist) {
				parser.mu.Lock()
				parser.errmsgs[name] = append(parser.errmsgs[name], fmt.Sprintf("%s calls nonexistent template %q", templateName, name))
				parser.mu.Unlock()
				continue
			}
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
			if err != nil {
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
	g, ctx := errgroup.WithContext(ctx)
	templateParser, err := NewTemplateParser(ctx, nbrew, sitePrefix)
	if err != nil {
		return err
	}

	dirEntries, err := nbrew.FS.ReadDir(path.Join(sitePrefix, "output"))
	if err != nil {
		return err
	}
	for _, dirEntry := range dirEntries {
		name, isDir := dirEntry.Name(), dirEntry.IsDir()
		if isDir {
			if name == "images" || name == "themes" || strings.HasPrefix(name, ".") {
				continue
			}
			err := RemoveAll(nbrew.FS, path.Join(sitePrefix, "output", name))
			if err != nil {
				return err
			}
		}
		err := nbrew.FS.Remove(path.Join(sitePrefix, "output", name))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return err
		}
	}

	err = MkdirAll(nbrew.FS, path.Join(sitePrefix, "output/posts"), 0755)
	if err != nil {
		return err
	}

	file, err := nbrew.FS.Open(path.Join(sitePrefix, "output/themes/posts.html"))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		file, err = rootFS.Open("static/posts.html")
		if err != nil {
			return err
		}
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
	postsTmpl, err := templateParser.Parse(b.String())
	if err != nil {
		return err
	}

	file, err = nbrew.FS.Open(path.Join(sitePrefix, "output/themes/post.html"))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		file, err = rootFS.Open("static/post.html")
		if err != nil {
			return err
		}
	}
	fileInfo, err = file.Stat()
	if err != nil {
		return err
	}
	b.Reset()
	b.Grow(int(fileInfo.Size()))
	_, err = io.Copy(&b, file)
	if err != nil {
		return err
	}
	postTmpl, err := templateParser.Parse(b.String())
	if err != nil {
		return err
	}

	// Render index.html.
	file, err = nbrew.FS.Open(path.Join(sitePrefix, "pages/index.html"))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		file, err = rootFS.Open("static/index.html")
		if err != nil {
			return err
		}
	}
	fileInfo, err = file.Stat()
	if err != nil {
		return err
	}
	b.Reset()
	b.Grow(int(fileInfo.Size()))
	_, err = io.Copy(&b, file)
	if err != nil {
		return err
	}
	indexTmpl, err := templateParser.Parse(b.String())
	if err != nil {
		return err
	}
	err = MkdirAll(nbrew.FS, path.Join(sitePrefix, "output"), 0755)
	if err != nil {
		return err
	}
	readerFrom, err := nbrew.FS.OpenReaderFrom(path.Join(sitePrefix, "output/index.html"), 0644)
	if err != nil {
		return err
	}
	pipeReader, pipeWriter := io.Pipe()
	ch := make(chan error, 1)
	go func() {
		_, err := readerFrom.ReadFrom(pipeReader)
		ch <- err
	}()
	defer pipeReader.Close()
	err = indexTmpl.Execute(&ctxWriter{ctx: ctx, dest: pipeWriter}, nil)
	pipeWriter.CloseWithError(err)
	if err != nil {
		return err
	}
	err = <-ch
	if err != nil {
		return err
	}

	// Render posts.
	err = fs.WalkDir(nbrew.FS, path.Join(sitePrefix, "posts"), func(filePath string, dirEntry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		isDir := dirEntry.IsDir()
		relativePath := strings.Trim(strings.TrimPrefix(filePath, path.Join(sitePrefix, "posts")), "/")
		segments := strings.Split(relativePath, "/")
		var category, name string
		if isDir {
			if len(segments) > 1 {
				return fs.SkipDir
			}
			category = segments[0]
		} else {
			if len(segments) > 2 {
				return nil
			}
			if len(segments) == 2 {
				category, name = segments[0], segments[1]
			} else {
				name = segments[0]
			}
		}
		ext := path.Ext(name)
		g.Go(func() error {
			if isDir {
				err = MkdirAll(nbrew.FS, path.Join(sitePrefix, "output/posts", category), 0755)
				if err != nil {
					return err
				}
				readerFrom, err := nbrew.FS.OpenReaderFrom(path.Join(sitePrefix, "output/posts", category, "index.html"), 0644)
				if err != nil {
					return err
				}
				pipeReader, pipeWriter := io.Pipe()
				ch := make(chan error, 1)
				go func() {
					_, err := readerFrom.ReadFrom(pipeReader)
					ch <- err
				}()
				defer pipeReader.Close()
				err = postsTmpl.Execute(&ctxWriter{ctx: ctx, dest: pipeWriter}, struct {
					Category string
				}{
					Category: category,
				})
				pipeWriter.CloseWithError(err)
				if err != nil {
					return err
				}
				return <-ch
			}
			if ext != ".md" && ext != ".txt" {
				return nil
			}
			file, err := nbrew.FS.Open(path.Join(sitePrefix, "posts", category, name))
			if err != nil {
				return err
			}
			buf := bufPool.Get().(*bytes.Buffer)
			buf.Reset()
			defer bufPool.Put(buf)
			_, err = buf.ReadFrom(file)
			if err != nil {
				return err
			}
			// title
			var title string
			var line []byte
			remainder := buf.Bytes()
			for len(remainder) > 0 {
				line, remainder, _ = bytes.Cut(remainder, []byte("\n"))
				line = bytes.TrimSpace(line)
				if len(line) == 0 {
					continue
				}
				title = stripMarkdownStyles(line)
				break
			}
			// content
			var b strings.Builder
			err = goldmarkMarkdown.Convert(buf.Bytes(), &b)
			if err != nil {
				return err
			}
			content := template.HTML(b.String())
			// createdAt
			var createdAt time.Time
			prefix, _, ok := strings.Cut(name, "-")
			if ok && len(prefix) > 0 && len(prefix) <= 8 {
				b, _ := base32Encoding.DecodeString(fmt.Sprintf("%08s", prefix))
				if len(b) == 5 {
					var timestamp [8]byte
					copy(timestamp[len(timestamp)-5:], b)
					createdAt = time.Unix(int64(binary.BigEndian.Uint64(timestamp[:])), 0)
				}
			}
			// UpdatedAt
			fileInfo, err := dirEntry.Info()
			if err != nil {
				return err
			}
			updatedAt := fileInfo.ModTime()
			err = MkdirAll(nbrew.FS, path.Join(sitePrefix, "output/posts", category, strings.TrimSuffix(name, ext)), 0755)
			if err != nil {
				return err
			}
			readerFrom, err := nbrew.FS.OpenReaderFrom(path.Join(sitePrefix, "output/posts", category, strings.TrimSuffix(name, ext), "index.html"), 0644)
			if err != nil {
				return err
			}
			pipeReader, pipeWriter := io.Pipe()
			ch := make(chan error, 1)
			go func() {
				_, err := readerFrom.ReadFrom(pipeReader)
				ch <- err
			}()
			defer pipeReader.Close()
			err = postTmpl.Execute(&ctxWriter{ctx: ctx, dest: pipeWriter}, Post{
				URL:       templateParser.siteURL + "/" + path.Join("posts", category, strings.TrimSuffix(name, path.Ext(name))) + "/",
				Category:  category,
				Name:      name,
				Title:     title,
				Content:   content,
				CreatedAt: createdAt,
				UpdatedAt: updatedAt,
			})
			pipeWriter.CloseWithError(err)
			if err != nil {
				return err
			}
			return <-ch
		})
		return nil
	})
	if err != nil {
		return err
	}

	// Render pages.
	err = fs.WalkDir(nbrew.FS, path.Join(sitePrefix, "pages"), func(filePath string, dirEntry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		g.Go(func() error {
			if dirEntry.IsDir() {
				return nil
			}
			relativePath := strings.Trim(strings.TrimPrefix(filePath, path.Join(sitePrefix, "pages")), "/")
			ext := path.Ext(relativePath)
			if ext != ".html" {
				return nil
			}
			file, err := nbrew.FS.Open(path.Join(sitePrefix, "pages", relativePath))
			if err != nil {
				return err
			}
			var b strings.Builder
			_, err = io.Copy(&b, file)
			if err != nil {
				return err
			}
			tmpl, err := templateParser.Parse(b.String())
			if err != nil {
				return err
			}
			if relativePath == "index.html" {
				// We already rendered index.html above, return.
				return nil
			}
			outputPath := path.Join(sitePrefix, "output", strings.TrimSuffix(relativePath, ext), "index.html")
			err = MkdirAll(nbrew.FS, path.Dir(outputPath), 0755)
			if err != nil {
				return err
			}
			writer, err := nbrew.FS.WithContext(ctx).OpenWriter(outputPath, 0644)
			if err != nil {
				return err
			}
			defer writer.Close()
			err = tmpl.Execute(writer, nil)
			if err != nil {
				return err
			}
			return writer.Close()
		})
		return nil
	})
	if err != nil {
		return err
	}
	err = g.Wait()
	if err != nil {
		return err
	}
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

type Post = struct {
	URL       string
	Category  string
	Name      string
	Title     string
	Preview   string
	Content   template.HTML
	CreatedAt time.Time
	UpdatedAt time.Time
}

func (nbrew *Notebrew) getPosts(ctx context.Context, sitePrefix, category string) ([]Post, error) {
	siteURL := nbrew.Scheme + nbrew.ContentDomain
	if strings.Contains(sitePrefix, ".") {
		siteURL = "https://" + sitePrefix
	} else if sitePrefix != "" {
		switch nbrew.MultisiteMode {
		case "subdomain":
			siteURL = nbrew.Scheme + strings.TrimPrefix(sitePrefix, "@") + "." + nbrew.ContentDomain
		case "subdirectory":
			siteURL = nbrew.Scheme + nbrew.ContentDomain + "/" + sitePrefix
		}
	}
	if category != urlSafe(category) {
		return nil, fs.ErrNotExist
	}
	fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, "posts", category))
	if err != nil {
		return nil, err
	}
	if !fileInfo.IsDir() {
		return nil, nil
	}
	dirEntries, err := nbrew.FS.ReadDir(path.Join(sitePrefix, "posts", category))
	if err != nil {
		return nil, err
	}
	var posts []Post
	for _, dirEntry := range dirEntries {
		err := ctx.Err()
		if err != nil {
			return nil, err
		}
		if dirEntry.IsDir() {
			continue
		}
		name := dirEntry.Name()
		ext := path.Ext(name)
		if ext != ".md" && ext != ".txt" {
			continue
		}
		fileInfo, err := dirEntry.Info()
		if err != nil {
			return nil, err
		}
		var createdAt time.Time
		prefix, _, ok := strings.Cut(name, "-")
		if ok && len(prefix) > 0 && len(prefix) <= 8 {
			b, _ := base32Encoding.DecodeString(fmt.Sprintf("%08s", prefix))
			if len(b) == 5 {
				var timestamp [8]byte
				copy(timestamp[len(timestamp)-5:], b)
				createdAt = time.Unix(int64(binary.BigEndian.Uint64(timestamp[:])), 0)
			}
		}
		post := Post{
			URL:       siteURL + "/" + path.Join("posts", category, strings.TrimSuffix(name, path.Ext(name))) + "/",
			Category:  category,
			Name:      name,
			CreatedAt: createdAt,
			UpdatedAt: fileInfo.ModTime(),
		}
		posts = append(posts, post)
	}
	slices.SortFunc(posts, func(p1, p2 Post) int {
		if p1.CreatedAt.Equal(p2.CreatedAt) {
			return 0
		}
		if p1.CreatedAt.Before(p2.CreatedAt) {
			return 1
		}
		return -1
	})
	g, ctx := errgroup.WithContext(ctx)
	g.SetLimit(runtime.NumCPU())
	for i := range posts {
		post := &posts[i]
		g.Go(func() error {
			file, err := nbrew.FS.Open(path.Join(sitePrefix, "posts", post.Category, post.Name))
			if err != nil {
				return err
			}
			reader := bufio.NewReader(file)
			proceed := true
			for proceed {
				err := ctx.Err()
				if err != nil {
					return err
				}
				line, err := reader.ReadBytes('\n')
				if err != nil {
					proceed = false
				}
				line = bytes.TrimSpace(line)
				if len(line) == 0 {
					continue
				}
				if post.Title == "" {
					post.Title = stripMarkdownStyles(line)
					continue
				}
				post.Preview = stripMarkdownStyles(line)
				break
			}
			return nil
		})
	}
	err = g.Wait()
	if err != nil {
		return nil, err
	}
	return posts, nil
}
