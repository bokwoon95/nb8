package nb8

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"encoding/json"
	"errors"
	"hash"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"slices"
	"strings"
	"time"
)

func (nbrew *Notebrew) file(w http.ResponseWriter, r *http.Request, username, sitePrefix, filePath string, fileInfo fs.FileInfo) {
	type FileEntry struct {
		Name    string     `json:"name"`
		Size    int64      `json:"size"`
		ModTime time.Time `json:"modTime"`
	}
	type Response struct {
		Status         Error      `json:"status"`
		ContentDomain  string     `json:"contentDomain,omitempty"`
		Username       string     `json:"username,omitempty"`
		SitePrefix     string     `json:"sitePrefix,omitempty"`
		Path           string     `json:"path"`
		IsDir          bool       `json:"isDir,omitempty"`
		ModTime        time.Time `json:"modTime,omitempty"`
		Size           int64      `json:"size,omitempty"`
		Content        string     `json:"content,omitempty"`
		ContentType    string     `json:"contentType,omitempty"`
		AssetDir       string     `json:"assetDir,omitempty"`
		TemplateErrors []string   `json:"templateErrors,omitempty"`
	}
	// asset: name size modtime
	fileType, ok := fileTypes[path.Ext(filePath)]
	if !ok {
		notFound(w, r)
		return
	}
	segments := strings.Split(filePath, "/")
	isEditableText := false
	switch fileType.Ext {
	case ".html", ".css", ".js", ".md", ".txt":
		if segments[0] != "output" {
			isEditableText = true
		} else if len(segments) > 1 && segments[0] == "output" && segments[1] == "themes" {
			isEditableText = true
		} else if fileType.Ext == ".css" || fileType.Ext == ".js" {
			isEditableText = true
		}
	}

	r.Body = http.MaxBytesReader(w, r.Body, 15<<20 /* 15MB */)
	switch r.Method {
	case "GET":
		err := r.ParseForm()
		if err != nil {
			badRequest(w, r, err)
			return
		}

		var response Response
		_, err = nbrew.getSession(r, "flash", &response)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		nbrew.clearSession(w, r, "flash")
		response.ContentDomain = nbrew.ContentDomain
		response.Username = username
		response.SitePrefix = sitePrefix
		response.Path = filePath
		response.IsDir = fileInfo.IsDir()
		response.ModTime = fileInfo.ModTime()
		response.Size = fileInfo.Size()
		response.ContentType = fileType.ContentType
		response.Status = Success
		if isEditableText {
			file, err := nbrew.FS.Open(path.Join(sitePrefix, filePath))
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			var b strings.Builder
			b.Grow(int(fileInfo.Size()))
			_, err = io.Copy(&b, file)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			response.Content = b.String()
		}

		accept, _, _ := mime.ParseMediaType(r.Header.Get("Accept"))
		if accept == "application/json" {
			w.Header().Set("Content-Type", "application/json")
			encoder := json.NewEncoder(w)
			encoder.SetEscapeHTML(false)
			err := encoder.Encode(&response)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
			}
			return
		}

		if !isEditableText {
			if fileType.Ext == ".html" {
				// Serve .html files as text/plain so that users can see its
				// raw value.
				w.Header().Set("Content-Type", "text/plain; charset=utf-8")
			}
			serveFile(w, r, nbrew.FS, path.Join(sitePrefix, filePath))
			return
		}

		var pagePath string
		if len(segments) > 2 && segments[0] == "output" && segments[1] != "posts" && (fileType.Ext == ".css" || fileType.Ext == ".js") {
			pageSegments := slices.Clone(segments[:len(segments)-1])
			pageSegments[0] = "pages"
			pageSegments[len(pageSegments)-1] += ".html"
			pagePath = strings.Join(pageSegments, "/")
		}

		// name, path
		// script.js, join admin sitePrefix output/abcd script.js

		// posts => .jpeg, .jpg, .png, .webp, .gif
		// pages => .jpeg, .jpg, .png, .webp, .gif, .css, .js

		funcMap := map[string]any{
			"join":             path.Join,
			"dir":              path.Dir,
			"base":             path.Base,
			"fileSizeToString": fileSizeToString,
			"stylesCSS":        func() template.CSS { return template.CSS(stylesCSS) },
			"baselineJS":       func() template.JS { return template.JS(baselineJS) },
			"longURL":          func() string { return longURL(nbrew.Scheme, sitePrefix, nbrew.ContentDomain) },
			"shortURL":         func() string { return shortURL(nbrew.Scheme, sitePrefix, nbrew.ContentDomain) },
			"hasDatabase":      func() bool { return nbrew.DB != nil },
			"referer":          func() string { return r.Referer() },
			"safeHTML":         func(s string) template.HTML { return template.HTML(s) },
			"pagePath":         func() string { return pagePath },
			"head": func(s string) string {
				head, _, _ := strings.Cut(s, "/")
				return head
			},
			"tail": func(s string) string {
				_, tail, _ := strings.Cut(s, "/")
				return tail
			},
		}
		tmpl, err := template.New("file.html").Funcs(funcMap).ParseFS(rootFS, "embed/file.html")
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		contentSecurityPolicy(w, "", false)
		executeTemplate(w, r, fileInfo.ModTime(), tmpl, &response)
	case "POST":
		writeResponse := func(w http.ResponseWriter, r *http.Request, response Response) {
			accept, _, _ := mime.ParseMediaType(r.Header.Get("Accept"))
			if accept == "application/json" {
				w.Header().Set("Content-Type", "application/json")
				encoder := json.NewEncoder(w)
				encoder.SetEscapeHTML(false)
				err := encoder.Encode(&response)
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
				}
				return
			}
			err := nbrew.setSession(w, r, "flash", &response)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			http.Redirect(w, r, nbrew.Scheme+nbrew.Domain+"/"+path.Join("admin", sitePrefix, filePath), http.StatusFound)
		}
		if !isEditableText {
		}
		// would you allow updating non-text files?

		var request struct {
			Content string `json:"content"`
		}
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		switch contentType {
		case "application/json":
			err := json.NewDecoder(r.Body).Decode(&request)
			if err != nil {
				badRequest(w, r, err)
				return
			}
		case "application/x-www-form-urlencoded", "multipart/form-data":
			if contentType == "multipart/form-data" {
				err := r.ParseMultipartForm(15 << 20 /* 15MB */)
				if err != nil {
					badRequest(w, r, err)
					return
				}
			} else {
				err := r.ParseForm()
				if err != nil {
					badRequest(w, r, err)
					return
				}
			}
			request.Content = r.Form.Get("content")
		default:
			unsupportedContentType(w, r)
			return
		}

		response := Response{
			Path:    filePath,
			IsDir:   fileInfo.IsDir(),
			ModTime: fileInfo.ModTime(),
			Content: request.Content,
		}

		if nbrew.DB != nil {
			// TODO: check if the owner has exceeded his storage limit, then
			// defer a function that will calculate and update the new storage
			// used after the file has been saved.
		}

		writer, err := nbrew.FS.OpenWriter(path.Join(sitePrefix, filePath), 0644)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		defer writer.Close()
		_, err = io.Copy(writer, strings.NewReader(request.Content))
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		err = writer.Close()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}

		segments := strings.Split(filePath, "/")
		if segments[0] == "posts" || segments[0] == "pages" || (len(segments) > 2 && segments[0] == "output" && segments[1] == "themes") {
			err = http.NewResponseController(w).SetWriteDeadline(time.Now().Add(3 * time.Minute))
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			// TODO: regenerate site or update the output accordingly
		}
		response.Status = UpdateSuccess
		writeResponse(w, r, response)
	default:
		methodNotAllowed(w, r)
	}
}

func serveFile(w http.ResponseWriter, r *http.Request, fsys fs.FS, name string) {
	if r.Method != "GET" {
		methodNotAllowed(w, r)
		return
	}

	var fileType FileType
	ext := path.Ext(name)
	if ext == ".webmanifest" {
		fileType.Ext = ".webmanifest"
		fileType.ContentType = "application/manifest+json"
		fileType.IsGzippable = true
	} else {
		fileType = fileTypes[ext]
	}
	if fileType.Ext == "" {
		notFound(w, r)
		return
	}

	file, err := fsys.Open(name)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			notFound(w, r)
			return
		}
		getLogger(r.Context()).Error(err.Error())
		internalServerError(w, r, err)
		return
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		internalServerError(w, r, err)
		return
	}
	if fileInfo.IsDir() {
		notFound(w, r)
		return
	}

	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	hasher := hashPool.Get().(hash.Hash)
	hasher.Reset()
	defer hashPool.Put(hasher)

	multiWriter := io.MultiWriter(buf, hasher)
	if !fileType.IsGzippable {
		_, err = io.Copy(multiWriter, file)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
	} else {
		gzipWriter := gzipPool.Get().(*gzip.Writer)
		gzipWriter.Reset(multiWriter)
		defer gzipPool.Put(gzipWriter)
		_, err = io.Copy(gzipWriter, file)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		err = gzipWriter.Close()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
	}

	b := bytesPool.Get().(*[]byte)
	*b = (*b)[:0]
	defer bytesPool.Put(b)

	if _, ok := w.Header()["Content-Type"]; !ok {
		contentType := fileType.ContentType
		if strings.HasPrefix(contentType, "text") {
			contentType += "; charset=utf-8"
		}
		w.Header().Set("Content-Type", contentType)
	}
	if fileType.IsGzippable {
		w.Header().Set("Content-Encoding", "gzip")
	}
	w.Header().Set("ETag", `"`+hex.EncodeToString(hasher.Sum(*b))+`"`)
	http.ServeContent(w, r, "", fileInfo.ModTime(), bytes.NewReader(buf.Bytes()))
}
