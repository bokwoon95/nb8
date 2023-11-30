package nb8

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/binary"
	"encoding/json"
	"encoding/xml"
	"errors"
	"fmt"
	"html/template"
	"io"
	"io/fs"
	"math"
	"path"
	"slices"
	"strconv"
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

type cacheEntry struct {
	template *template.Template
	once     sync.Once
}

type SiteGenerator struct {
	domain               string
	fsys                 FS
	sitePrefix           string
	site                 Site
	markdown             goldmark.Markdown
	mu                   sync.Mutex
	cache                map[string]*cacheEntry
	templateCache        map[string]*template.Template
	templateInProgress   map[string]chan struct{}
	post                 *template.Template
	postErr              error
	postOnce             sync.Once
	postList             *template.Template
	postListErr          error
	postListOnce         sync.Once
	gzipGeneratedContent bool
	// TODO: eventually make these configurable
	postsPerPage map[string]int // default 100
}

type Site struct {
	Title      string
	Favicon    string
	Lang       string
	Categories []string
}

type SiteGeneratorConfig struct {
	ContentDomain        string
	FS                   FS
	SitePrefix           string
	Title                string
	Favicon              string
	Lang                 string
	CodeStyle            string
	GzipGeneratedContent bool
	PostPerPage          map[string]int
}

func NewSiteGenerator(config SiteGeneratorConfig) (*SiteGenerator, error) {
	if config.Favicon == "" {
		config.Favicon = "data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 10 10%22><text y=%221em%22 font-size=%228%22>☕</text></svg>"
	} else {
		char, size := utf8.DecodeRuneInString(config.Favicon)
		if size == len(config.Favicon) {
			config.Favicon = "data:image/svg+xml,<svg xmlns=%22http://www.w3.org/2000/svg%22 viewBox=%220 0 10 10%22><text y=%221em%22 font-size=%228%22>" + string(char) + "</text></svg>"
		}
	}
	if config.Title == "" {
		config.Title = "My blog"
	}
	if config.Lang == "" {
		config.Lang = "en"
	}
	if config.CodeStyle == "" {
		config.CodeStyle = "dracula"
	}
	if config.ContentDomain == "" {
		return nil, fmt.Errorf("ContentDomain cannot be empty")
	}
	var domain string
	if strings.Contains(config.SitePrefix, ".") {
		domain = config.SitePrefix
	} else if config.SitePrefix != "" {
		domain = config.SitePrefix + "." + config.ContentDomain
	} else {
		domain = config.ContentDomain
	}
	siteGen := &SiteGenerator{
		domain:     domain,
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
		mu:                   sync.Mutex{},
		templateCache:        make(map[string]*template.Template),
		templateInProgress:   make(map[string]chan struct{}),
		gzipGeneratedContent: config.GzipGeneratedContent,
	}
	dirEntries, err := siteGen.fsys.ReadDir(path.Join(siteGen.sitePrefix, "posts"))
	if err != nil {
		return nil, err
	}
	for _, dirEntry := range dirEntries {
		if dirEntry.IsDir() {
			siteGen.site.Categories = append(siteGen.site.Categories, dirEntry.Name())
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
	Site             Site
	Parent           string
	Name             string
	ChildPages       []Page
	Markdown         map[string]template.HTML
	Images           []Image
	ModificationTime time.Time
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
	pageData.ModificationTime = fileInfo.ModTime()

	// Prepare the page template.
	tmpl, err := siteGen.parseTemplate(ctx, path.Base(name), b.String(), nil)
	if err != nil {
		return err
	}

	g1, ctx1 := errgroup.WithContext(ctx)
	var outputDir string
	if name == "index.html" {
		outputDir = path.Join(siteGen.sitePrefix, "output")
	} else {
		outputDir = path.Join(siteGen.sitePrefix, "output", strings.TrimSuffix(name, ext))
	}
	g1.Go(func() error {
		g2, ctx2 := errgroup.WithContext(ctx1)
		markdownMu := sync.Mutex{}
		dirFiles, err := ReadDirFiles(siteGen.fsys.WithContext(ctx2), outputDir)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		for _, dirFile := range dirFiles {
			dirFile := dirFile
			if dirFile.IsDir() {
				continue
			}
			name := dirFile.Name()
			fileType := fileTypes[path.Ext(name)]
			if strings.HasPrefix(fileType.ContentType, "image") {
				pageData.Images = append(pageData.Images, Image{
					Parent: strings.TrimSuffix(name, ext),
					Name:   name,
				})
				continue
			}
			if strings.HasPrefix(fileType.ContentType, "text/markdown") {
				g2.Go(func() error {
					file, err := dirFile.Open()
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
					pageData.Markdown[name] = template.HTML(b.String())
					markdownMu.Unlock()
					return nil
				})
				continue
			}
		}
		return g2.Wait()
	})
	g1.Go(func() error {
		g2, ctx2 := errgroup.WithContext(ctx1)
		dirFiles, err := ReadDirFiles(siteGen.fsys.WithContext(ctx2), path.Join(siteGen.sitePrefix, "pages", strings.TrimSuffix(name, ext)))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		n := 0
		for _, dirFile := range dirFiles {
			if strings.HasSuffix(dirFile.Name(), ".html") {
				dirFiles[n] = dirFile
				n++
			}
		}
		dirFiles = dirFiles[:n]
		pageData.ChildPages = make([]Page, len(dirFiles))
		for i, dirFile := range dirFiles {
			i, dirFile := i, dirFile
			g2.Go(func() error {
				file, err := dirFile.Open()
				if err != nil {
					return err
				}
				defer file.Close()
				reader := readerPool.Get().(*bufio.Reader)
				reader.Reset(file)
				defer readerPool.Put(reader)
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
					Parent: strings.TrimSuffix(name, ext),
					Name:   dirFile.Name(),
					Title:  buf.String(),
				}
				return nil
			})
		}
		return g2.Wait()
	})
	err = g1.Wait()
	if err != nil {
		return err
	}

	// Render the template contents into the output index.html.
	writer, err := siteGen.fsys.WithContext(ctx).OpenWriter(path.Join(outputDir, "index.html"), 0644)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		err := MkdirAll(siteGen.fsys.WithContext(ctx), outputDir, 0755)
		if err != nil {
			return err
		}
		writer, err = siteGen.fsys.WithContext(ctx).OpenWriter(path.Join(outputDir, "index.html"), 0644)
		if err != nil {
			return err
		}
	}
	defer writer.Close()
	if siteGen.gzipGeneratedContent {
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
	} else {
		err = tmpl.Execute(writer, &pageData)
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
	Site             Site
	Category         string
	Name             string
	Title            string
	Content          template.HTML
	Images           []Image
	CreationTime     time.Time
	ModificationTime time.Time
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
	// Obtain the creation time from the timestamp prefix.
	prefix, _, ok := strings.Cut(name, "-")
	if !ok || len(prefix) == 0 || len(prefix) > 8 {
		return fmt.Errorf("%s is not a valid post, missing timestamp prefix", name)
	}
	b, _ := base32Encoding.DecodeString(fmt.Sprintf("%08s", prefix))
	if len(b) != 5 {
		return fmt.Errorf("%s is not a valid post, %s is not a timestamp prefix", name, prefix)
	}
	var timestamp [8]byte
	copy(timestamp[len(timestamp)-5:], b)
	postData.CreationTime = time.Unix(int64(binary.BigEndian.Uint64(timestamp[:])), 0)

	siteGen.postOnce.Do(func() {
		// Open the post template file and read its contents.
		file, err := siteGen.fsys.WithContext(ctx).Open(path.Join(siteGen.sitePrefix, "output/themes/post.html"))
		if err != nil {
			// If the user's post.html doesn't exist, fall back to our built-in
			// post.html.
			if !errors.Is(err, fs.ErrNotExist) {
				siteGen.postErr = err
				return
			}
			file, err = rootFS.Open("static/post.html")
			if err != nil {
				siteGen.postErr = err
				return
			}
		}
		defer file.Close()
		fileInfo, err := file.Stat()
		if err != nil {
			siteGen.postErr = err
			return
		}
		if fileInfo.IsDir() {
			siteGen.postErr = fmt.Errorf("%s is not a template", name)
			return
		}
		var b strings.Builder
		b.Grow(int(fileInfo.Size()))
		_, err = io.Copy(&b, file)
		if err != nil {
			siteGen.postErr = err
			return
		}
		err = file.Close()
		if err != nil {
			siteGen.postErr = err
			return
		}

		// Prepare the post template.
		post, err := siteGen.parseTemplate(ctx, "/themes/post.html", b.String(), []string{"/themes/post.html"})
		if err != nil {
			siteGen.postErr = err
			return
		}
		siteGen.post = post
	})
	if siteGen.postErr != nil {
		return siteGen.postErr
	}

	// Get images belonging to the post.
	g1, ctx1 := errgroup.WithContext(ctx)
	outputDir := path.Join(siteGen.sitePrefix, "output/posts", strings.TrimSuffix(name, ext))
	g1.Go(func() error {
		dirEntries, err := siteGen.fsys.WithContext(ctx1).ReadDir(outputDir)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				return nil
			}
			return err
		}
		for _, dirEntry := range dirEntries {
			name := dirEntry.Name()
			if dirEntry.IsDir() {
				continue
			}
			fileType := fileTypes[path.Ext(name)]
			if strings.HasPrefix(fileType.ContentType, "image") {
				postData.Images = append(postData.Images, Image{
					Parent: path.Join("posts", strings.TrimSuffix(name, ext)),
					Name:   name,
				})
				continue
			}
		}
		return nil
	})

	// Read the post markdown content and convert it to HTML.
	g1.Go(func() error {
		file, err := siteGen.fsys.WithContext(ctx1).Open(path.Join(siteGen.sitePrefix, "posts", name))
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
		// ModificationTime
		postData.ModificationTime = fileInfo.ModTime()
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

	err := g1.Wait()
	if err != nil {
		return err
	}

	// Render the template contents into the output index.html.
	writer, err := siteGen.fsys.WithContext(ctx).OpenWriter(path.Join(outputDir, "index.html"), 0644)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			return err
		}
		err := MkdirAll(siteGen.fsys.WithContext(ctx), outputDir, 0755)
		if err != nil {
			return err
		}
		writer, err = siteGen.fsys.WithContext(ctx).OpenWriter(path.Join(outputDir, "index.html"), 0644)
		if err != nil {
			return err
		}
	}
	defer writer.Close()
	if siteGen.gzipGeneratedContent {
		gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
		gzipWriter.Reset(writer)
		defer gzipWriterPool.Put(gzipWriter)
		err = siteGen.post.Execute(gzipWriter, &postData)
		if err != nil {
			return err
		}
		err = gzipWriter.Close()
		if err != nil {
			return err
		}
	} else {
		err = siteGen.post.Execute(writer, &postData)
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

type Post struct {
	Category         string
	Name             string
	Title            string
	Preview          string
	Content          template.HTML
	CreationTime     time.Time
	ModificationTime time.Time
}

type PostListData struct {
	Site       Site
	Category   string
	Pagination Pagination
	Posts      []Post
}

func (siteGen *SiteGenerator) GeneratePostList(ctx context.Context, category string) error {
	// Chris Coyier OPML: https://chriscoyier.net/files/personal-developer-blogs.xml
	siteGen.postListOnce.Do(func() {
		// Open the post list template file and read its contents.
		file, err := siteGen.fsys.WithContext(ctx).Open(path.Join(siteGen.sitePrefix, "output/themes/post-list.html"))
		if err != nil {
			// If the user's post-list.html doesn't exist, fall back to our
			// built-in post-list.html.
			if !errors.Is(err, fs.ErrNotExist) {
				siteGen.postListErr = err
				return
			}
			file, err = rootFS.Open("static/post-list.html")
			if err != nil {
				siteGen.postListErr = err
				return
			}
		}
		defer file.Close()
		fileInfo, err := file.Stat()
		if err != nil {
			siteGen.postListErr = err
			return
		}
		if fileInfo.IsDir() {
			siteGen.postListErr = fmt.Errorf("/themes/post-list.html is not a template")
			return
		}
		var b strings.Builder
		b.Grow(int(fileInfo.Size()))
		_, err = io.Copy(&b, file)
		if err != nil {
			siteGen.postListErr = err
			return
		}
		err = file.Close()
		if err != nil {
			siteGen.postListErr = err
			return
		}

		// Prepare the postList list template.
		postList, err := siteGen.parseTemplate(ctx, "/themes/post-list.html", b.String(), []string{"/themes/post-list.html"})
		if err != nil {
			siteGen.postListErr = err
			return
		}
		siteGen.postList = postList
	})
	if siteGen.postListErr != nil {
		return siteGen.postListErr
	}
	postsPerPage := siteGen.postsPerPage[category]
	if postsPerPage <= 0 {
		postsPerPage = 100
	}

	dirFiles, err := ReadDirFiles(siteGen.fsys.WithContext(ctx), path.Join(siteGen.sitePrefix, "posts", category))
	if err != nil {
		return err
	}
	slices.Reverse(dirFiles)
	n := 0
	creationTimes := make([]time.Time, 0, len(dirFiles))
	for _, dirFile := range dirFiles {
		name := dirFile.Name()
		if !strings.HasSuffix(name, ".md") {
			continue
		}
		prefix, _, ok := strings.Cut(name, "-")
		if !ok || prefix == "" || len(prefix) > 8 {
			continue
		}
		b, _ := base32Encoding.DecodeString(fmt.Sprintf("%08s", prefix))
		if len(b) != 5 {
			continue
		}
		var timestamp [8]byte
		copy(timestamp[len(timestamp)-5:], b)
		dirFiles[n] = dirFile
		creationTimes = append(creationTimes, time.Unix(int64(binary.BigEndian.Uint64(timestamp[:])), 0))
	}
	dirFiles = dirFiles[:n]

	g1, ctx1 := errgroup.WithContext(ctx)
	lastPage := int(math.Ceil(float64(len(dirFiles)) / float64(postsPerPage)))
	for page := 1; page <= lastPage; page++ {
		currentPage := page
		g1.Go(func() error {
			err := ctx1.Err()
			if err != nil {
				return err
			}
			start := (currentPage - 1) * postsPerPage
			end := (currentPage * postsPerPage) - 1
			if currentPage == lastPage {
				end = len(dirFiles)
			}
			postListData := PostListData{
				Site:       siteGen.site,
				Category:   category,
				Pagination: NewPagination(currentPage, lastPage, 9),
				Posts:      make([]Post, (end-start)+1),
			}
			g2A, ctx2A := errgroup.WithContext(ctx1)
			for i, dirFile := range dirFiles[start:end] {
				i, dirFile := i, dirFile
				g2A.Go(func() error {
					err := ctx2A.Err()
					if err != nil {
						return err
					}
					file, err := dirFile.Open()
					if err != nil {
						return err
					}
					defer file.Close()
					fileInfo, err := file.Stat()
					if err != nil {
						return err
					}
					post := Post{
						Category:         postListData.Category,
						Name:             strings.TrimSuffix(fileInfo.Name(), ".md"),
						CreationTime:     creationTimes[start+i],
						ModificationTime: fileInfo.ModTime(),
					}
					if currentPage == 1 {
						buf := bufPool.Get().(*bytes.Buffer)
						buf.Reset()
						defer bufPool.Put(buf)
						_, err := buf.ReadFrom(file)
						if err != nil {
							return err
						}
						var line []byte
						remainder := buf.Bytes()
						for len(remainder) > 0 {
							line, remainder, _ = bytes.Cut(remainder, []byte("\n"))
							line = bytes.TrimSpace(line)
							if len(line) == 0 {
								continue
							}
							if post.Title == "" {
								post.Title = stripMarkdownStyles(line)
								continue
							}
							if post.Preview == "" {
								post.Preview = stripMarkdownStyles(line)
								continue
							}
							break
						}
						var b strings.Builder
						err = siteGen.markdown.Convert(buf.Bytes(), &b)
						if err != nil {
							return err
						}
						post.Content = template.HTML(b.String())
					} else {
						reader := readerPool.Get().(*bufio.Reader)
						reader.Reset(file)
						defer readerPool.Put(reader)
						done := false
						for !done {
							line, err := reader.ReadSlice('\n')
							if err != nil {
								if err != io.EOF {
									return err
								}
								done = true
							}
							line = bytes.TrimSpace(line)
							if len(line) == 0 {
								continue
							}
							if post.Title == "" {
								post.Title = stripMarkdownStyles(line)
								continue
							}
							if post.Preview == "" {
								post.Preview = stripMarkdownStyles(line)
								continue
							}
							break
						}
					}
					postListData.Posts[i] = post
					return nil
				})
			}
			err = g2A.Wait()
			if err != nil {
				return err
			}
			g2B, ctx2B := errgroup.WithContext(ctx1)
			if currentPage == 1 {
				outputDir := path.Join(siteGen.sitePrefix, "output/posts", postListData.Category)
				g2B.Go(func() error {
					feed := AtomFeed{
						Xmlns:   "http://www.w3.org/2005/Atom",
						ID:      "https://" + siteGen.domain,
						Title:   siteGen.site.Title,
						Updated: time.Now().UTC().Format("2006-01-02 15:04:05Z"),
						Link: []AtomLink{{
							Href: "https://" + siteGen.domain + "/" + path.Join("posts", postListData.Category) + "/atom.xml",
							Rel:  "self",
						}, {
							Href: "https://" + siteGen.domain + "/" + path.Join("posts", postListData.Category) + "/",
							Rel:  "alternate",
						}},
						Entry: make([]AtomEntry, len(postListData.Posts)),
					}
					for i, post := range postListData.Posts {
						// ID: tag:bokwoon.nbrew.io,yyyy-mm-dd:1jjdz28
						var timestamp [8]byte
						binary.BigEndian.PutUint64(timestamp[:], uint64(post.CreationTime.Unix()))
						prefix := strings.TrimLeft(base32Encoding.EncodeToString(timestamp[len(timestamp)-5:]), "0")
						feed.Entry[i] = AtomEntry{
							ID:        "tag:" + siteGen.domain + "," + post.CreationTime.UTC().Format("2006-01-02") + ":" + prefix,
							Title:     post.Title,
							Published: post.CreationTime.UTC().Format("2006-01-02 15:04:05Z"),
							Updated:   post.ModificationTime.UTC().Format("2006-01-02 15:04:05Z"),
							Link: []AtomLink{{
								Href: "https://" + siteGen.domain + "/" + path.Join("posts", post.Category, post.Name) + "/",
								Rel:  "alternate",
							}},
							Content: AtomContent{
								Type:    "html",
								Content: string(post.Content),
							},
						}
					}
					writer, err := siteGen.fsys.WithContext(ctx2B).OpenWriter(path.Join(outputDir, "atom.xml"), 0644)
					if err != nil {
						if !errors.Is(err, fs.ErrNotExist) {
							return err
						}
						err := MkdirAll(siteGen.fsys.WithContext(ctx2B), outputDir, 0755)
						if err != nil {
							return err
						}
						writer, err = siteGen.fsys.WithContext(ctx2B).OpenWriter(path.Join(outputDir, "atom.xml"), 0644)
						if err != nil {
							return err
						}
					}
					defer writer.Close()
					if siteGen.gzipGeneratedContent {
						gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
						gzipWriter.Reset(writer)
						defer gzipWriterPool.Put(gzipWriter)
						_, err := gzipWriter.Write([]byte(xml.Header))
						if err != nil {
							return err
						}
						err = xml.NewEncoder(gzipWriter).Encode(&feed)
						if err != nil {
							return err
						}
						err = gzipWriter.Close()
						if err != nil {
							return err
						}
					} else {
						_, err := writer.Write([]byte(xml.Header))
						if err != nil {
							return err
						}
						err = xml.NewEncoder(writer).Encode(&feed)
						if err != nil {
							return err
						}
					}
					err = writer.Close()
					if err != nil {
						return err
					}
					return nil
				})
				g2B.Go(func() error {
					writer, err := siteGen.fsys.WithContext(ctx2B).OpenWriter(path.Join(outputDir, "index.html"), 0644)
					if err != nil {
						if !errors.Is(err, fs.ErrNotExist) {
							return err
						}
						err := MkdirAll(siteGen.fsys.WithContext(ctx2B), outputDir, 0755)
						if err != nil {
							return err
						}
						writer, err = siteGen.fsys.WithContext(ctx2B).OpenWriter(path.Join(outputDir, "index.html"), 0644)
						if err != nil {
							return err
						}
					}
					defer writer.Close()
					if siteGen.gzipGeneratedContent {
						gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
						gzipWriter.Reset(writer)
						defer gzipWriterPool.Put(gzipWriter)
						err = siteGen.postList.Execute(gzipWriter, &postListData)
						if err != nil {
							return err
						}
						err = gzipWriter.Close()
						if err != nil {
							return err
						}
					} else {
						err = siteGen.postList.Execute(writer, &postListData)
						if err != nil {
							return err
						}
					}
					err = writer.Close()
					if err != nil {
						return err
					}
					return nil
				})
			}
			if lastPage > 1 {
				g2B.Go(func() error {
					outputDir := path.Join(siteGen.sitePrefix, "output/posts", postListData.Category, strconv.Itoa(currentPage))
					writer, err := siteGen.fsys.WithContext(ctx2B).OpenWriter(path.Join(outputDir, "index.html"), 0644)
					if err != nil {
						if !errors.Is(err, fs.ErrNotExist) {
							return err
						}
						err := MkdirAll(siteGen.fsys.WithContext(ctx2B), outputDir, 0755)
						if err != nil {
							return err
						}
						writer, err = siteGen.fsys.WithContext(ctx2B).OpenWriter(path.Join(outputDir, "index.html"), 0644)
						if err != nil {
							return err
						}
					}
					defer writer.Close()
					if siteGen.gzipGeneratedContent {
						gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
						gzipWriter.Reset(writer)
						defer gzipWriterPool.Put(gzipWriter)
						err = siteGen.postList.Execute(gzipWriter, &postListData)
						if err != nil {
							return err
						}
						err = gzipWriter.Close()
						if err != nil {
							return err
						}
					} else {
						err = siteGen.postList.Execute(writer, &postListData)
						if err != nil {
							return err
						}
					}
					err = writer.Close()
					if err != nil {
						return err
					}
					return nil
				})
			}
			err = g2B.Wait()
			if err != nil {
				return err
			}
			return nil
		})
	}
	err = g1.Wait()
	if err != nil {
		return err
	}
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
				// We found the template; add it to the slice and exit. Note
				// that the cachedTemplate may be nil, if parsing that template
				// had resulted in errors.
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

	mergedErrs := make(TemplateErrors)
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
		return nil, mergedErrs
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

type Pagination struct {
	First    string
	Previous string
	Current  string
	Next     string
	Last     string
	Numbers  []string
}

func NewPagination(currentPage, lastPage, visiblePages int) Pagination {
	const numConsecutiveNeighbours = 2
	if visiblePages%2 == 0 {
		panic("even number of visiblePages")
	}
	minVisiblePages := (numConsecutiveNeighbours * 2) + 1
	if visiblePages < minVisiblePages {
		panic("visiblePages cannot be lower than " + strconv.Itoa(minVisiblePages))
	}
	pagination := Pagination{
		First:   "1",
		Current: strconv.Itoa(currentPage),
		Last:    strconv.Itoa(lastPage),
	}
	previous := currentPage - 1
	if previous >= 1 {
		pagination.Previous = strconv.Itoa(previous)
	}
	next := currentPage + 1
	if next <= lastPage {
		pagination.Next = strconv.Itoa(next)
	}
	// If there are fewer pages than visible pages, iterate through all the
	// page numbers.
	if lastPage <= visiblePages {
		pagination.Numbers = make([]string, 0, lastPage)
		for page := 1; page <= lastPage; page++ {
			pagination.Numbers = append(pagination.Numbers, strconv.Itoa(page))
		}
		return pagination
	}
	// Slots corresponds to the available slots in pagination.Numbers, storing
	// the page numbers as integers. They will be converted to strings later.
	slots := make([]int, visiblePages)
	// A unit is a tenth of the maximum number of pages. The rationale is that
	// users have to paginate at most 10 such units to get from start to end,
	// no matter how many pages there are.
	unit := lastPage / 10
	if currentPage-1 < len(slots)>>1 {
		// If there are fewer pages on the left than half of the slots, the
		// current page will skew more towards the left. We fill in consecutive
		// page numbers from left to right, then fill in the remaining slots.
		numConsecutive := (currentPage - 1) + 1 + numConsecutiveNeighbours
		consecutiveStart := 0
		consecutiveEnd := numConsecutive - 1
		page := 1
		for i := consecutiveStart; i <= consecutiveEnd; i++ {
			slots[i] = page
			page += 1
		}
		// The last slot is always the last page.
		slots[len(slots)-1] = lastPage
		// Fill in the remaining slots with either an exponentially changing or
		// linearly changing number depending on which is more appropriate.
		remainingSlots := slots[consecutiveEnd+1 : len(slots)-1]
		delta := numConsecutiveNeighbours + len(remainingSlots)
		shift := 0
		for i := len(slots) - 2; i >= consecutiveEnd+1; i-- {
			exponentialNum := currentPage + unit>>shift
			linearNum := currentPage + delta
			if exponentialNum > linearNum && exponentialNum < lastPage {
				slots[i] = exponentialNum
			} else {
				slots[i] = linearNum
			}
			shift += 1
			delta -= 1
		}
	} else if lastPage-currentPage < len(slots)>>1 {
		// If there are fewer pages on the right than half of the slots, the
		// current page will skew more towards the right. We fill in
		// consecutive page numbers from the right to left, then fill in the
		// remaining slots.
		numConsecutive := (lastPage - currentPage) + 1 + numConsecutiveNeighbours
		consecutiveStart := len(slots) - 1
		consecutiveEnd := len(slots) - numConsecutive
		page := lastPage
		for i := consecutiveStart; i >= consecutiveEnd; i-- {
			slots[i] = page
			page -= 1
		}
		// The first slot is always the first page.
		slots[0] = 1
		// Fill in the remaining slots with either an exponentially changing or
		// linearly changing number depending on which is more appropriate.
		remainingSlots := slots[1:consecutiveEnd]
		delta := numConsecutiveNeighbours + len(remainingSlots)
		shift := 0
		for i := 1; i < consecutiveEnd; i++ {
			exponentialNum := currentPage - unit>>shift
			linearNum := currentPage - delta
			if exponentialNum < linearNum && exponentialNum > 1 {
				slots[i] = exponentialNum
			} else {
				slots[i] = linearNum
			}
			shift += 1
			delta -= 1
		}
	} else {
		// If we reach here, it means the current page is directly in the
		// center the slots. Fill in the consecutive band of numbers around the
		// center, then fill in the remaining slots to the left and to the
		// right.
		consecutiveStart := len(slots)>>1 - numConsecutiveNeighbours
		consecutiveEnd := len(slots)>>1 + numConsecutiveNeighbours
		page := currentPage - numConsecutiveNeighbours
		for i := consecutiveStart; i <= consecutiveEnd; i++ {
			slots[i] = page
			page += 1
		}
		// The first slot is always the first page.
		slots[0] = 1
		// The last slot is always the last page.
		slots[len(slots)-1] = lastPage
		// Fill in the remaining slots on the left with either an exponentially
		// changing or linearly changing number depending on which is more
		// appropriate.
		remainingSlots := slots[1:consecutiveStart]
		delta := numConsecutiveNeighbours + len(remainingSlots)
		shift := 0
		for i := 1; i < consecutiveStart; i++ {
			exponentialNum := currentPage - unit>>shift
			linearNum := currentPage - delta
			if exponentialNum < linearNum && exponentialNum > 1 {
				slots[i] = exponentialNum
			} else {
				slots[i] = linearNum
			}
			shift += 1
			delta -= 1
		}
		// Fill in the remaining slots on the right with either an exponentially
		// changing or linearly changing number depending on which is more
		// appropriate.
		remainingSlots = slots[consecutiveEnd+1 : len(slots)-1]
		delta = numConsecutiveNeighbours + len(remainingSlots)
		shift = 0
		for i := len(slots) - 2; i >= consecutiveEnd+1; i-- {
			exponentialNum := currentPage + unit>>shift
			linearNum := currentPage + delta
			if exponentialNum > linearNum && exponentialNum < lastPage {
				slots[i] = exponentialNum
			} else {
				slots[i] = linearNum
			}
			shift += 1
			delta -= 1
		}
	}
	// Convert the page numbers in the slots to strings.
	pagination.Numbers = make([]string, len(slots))
	for i, num := range slots {
		pagination.Numbers[i] = strconv.Itoa(num)
	}
	return pagination
}

func (p Pagination) All() []string {
	lastPage, err := strconv.Atoi(p.Last)
	if err != nil {
		return nil
	}
	numbers := make([]string, 0, lastPage)
	for page := 1; page <= lastPage; page++ {
		numbers = append(numbers, strconv.Itoa(page))
	}
	return numbers
}

type AtomFeed struct {
	XMLName xml.Name    `xml:"feed"`
	Xmlns   string      `xml:"xmlns,attr"`
	ID      string      `xml:"id"`
	Title   string      `xml:"title"`
	Updated string      `xml:"updated"`
	Link    []AtomLink  `xml:"link"` // rel=self, rel=alternate
	Entry   []AtomEntry `xml:"entry"`
}

type AtomEntry struct {
	ID        string      `xml:"id"`
	Title     string      `xml:"title"`
	Published string      `xml:"published"`
	Updated   string      `xml:"updated"`
	Link      []AtomLink  `xml:"link"` // rel=alternate
	Content   AtomContent `xml:"content"`
}

type AtomLink struct {
	Href string `xml:"href,attr"`
	Rel  string `xml:"rel,attr"`
}

type AtomContent struct {
	Type    string `xml:"type,attr"`
	Content string `xml:",chardata"`
}
