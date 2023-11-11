package nb8

import (
	"encoding/json"
	"html/template"
	"io"
	"io/fs"
	"mime"
	"net/http"
	"path"
	"strings"
	"time"
)

var extensionTypes = map[string]string{
	".html":  "text/html",
	".css":   "text/css",
	".js":    "text/javascript",
	".md":    "text/markdown",
	".txt":   "text/plain",
	".csv":   "text/csv",
	".tsv":   "text/tsv",
	".json":  "text/json",
	".xml":   "text/xml",
	".toml":  "text/toml",
	".yaml":  "text/yaml",
	".svg":   "image/svg",
	".ico":   "image/ico",
	".jpeg":  "image/jpeg",
	".jpg":   "image/jpeg",
	".png":   "image/png",
	".gif":   "image/gif",
	".eot":   "font/eot",
	".otf":   "font/otf",
	".ttf":   "font/ttf",
	".woff":  "font/woff",
	".woff2": "font/woff2",
	".gzip":  "gzip",
	".gz":    "gzip",
}

func (nbrew *Notebrew) file(w http.ResponseWriter, r *http.Request, username, sitePrefix, filePath string, fileInfo fs.FileInfo) {
	type Request struct {
		Content string `json:"content"`
	}
	type Response struct {
		Status        Error              `json:"status"`
		ContentDomain string             `json:"contentDomain,omitempty"`
		Username      string             `json:"username,omitempty"`
		SitePrefix    string             `json:"sitePrefix,omitempty"`
		Path          string             `json:"path"`
		IsDir         bool               `json:"isDir,omitempty"`
		ModTime       *time.Time         `json:"modTime,omitempty"`
		Type          string             `json:"type,omitempty"`
		Content       string             `json:"content,omitempty"`
		Location      string             `json:"location,omitempty"`
		Errors        map[string][]Error `json:"errors,omitempty"`
		StorageUsed   int64              `json:"storageUsed,omitempty"`
		StorageLimit  int64              `json:"storageLimit,omitempty"`
	}

	ext := path.Ext(filePath)
	typ := extensionTypes[ext]
	r.Body = http.MaxBytesReader(w, r.Body, 15<<20 /* 15MB */)
	switch r.Method {
	case "GET":
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
			var title string
			str := response.Content
			for {
				if str == "" {
					break
				}
				title, str, _ = strings.Cut(str, "\n")
				title = strings.TrimSpace(title)
				if title == "" {
					continue
				}
				title = stripMarkdownStyles([]byte(title))
				break
			}
			funcMap := map[string]any{
				"join":             path.Join,
				"dir":              path.Dir,
				"base":             path.Base,
				"fileSizeToString": fileSizeToString,
				"stylesCSS":        func() template.CSS { return template.CSS(stylesCSS) },
				"baselineJS":       func() template.JS { return template.JS(baselineJS) },
				"hasDatabase":      func() bool { return nbrew.DB != nil },
				"referer":          func() string { return r.Referer() },
				"title":            func() string { return title },
				"safeHTML":         func(s string) template.HTML { return template.HTML(s) },
				"head": func(s string) string {
					head, _, _ := strings.Cut(s, "/")
					return head
				},
				"tail": func(s string) string {
					_, tail, _ := strings.Cut(s, "/")
					return tail
				},
				"hasPrefix": func(s string, prefixes ...string) bool {
					for _, prefix := range prefixes {
						if strings.HasPrefix(s, prefix) {
							return true
						}
					}
					return false
				},
				"hasSuffix": func(s string, suffixes ...string) bool {
					for _, suffix := range suffixes {
						if strings.HasSuffix(s, suffix) {
							return true
						}
					}
					return false
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
		}
		err := r.ParseForm()
		if err != nil {
			badRequest(w, r, err)
			return
		}
		if fileInfo == nil {
			fileInfo, err = fs.Stat(nbrew.FS, path.Join(".", sitePrefix, filePath))
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
		}

		_, tail, _ := strings.Cut(filePath, "/")

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
		response.Type = typ
		response.IsDir = fileInfo.IsDir()
		modTime := fileInfo.ModTime()
		if !modTime.IsZero() {
			response.ModTime = &modTime
		}
		if response.Status != "" {
			writeResponse(w, r, response)
			return
		}
		if strings.HasPrefix(response.Type, "image") || strings.HasPrefix(response.Type, "font") || response.Type == "gzip" {
			response.Location = nbrew.Scheme + nbrew.Domain + "/" + path.Join("admin", sitePrefix, tail)
		} else if strings.HasPrefix(response.Type, "text") {
			file, err := nbrew.FS.Open(path.Join(sitePrefix, filePath))
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			defer file.Close()
			var b strings.Builder
			b.Grow(int(fileInfo.Size()))
			_, err = io.Copy(&b, file)
			if err != nil {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			response.Content = b.String()
		} else {
			notFound(w, r)
			return
		}
		response.Status = Success
		writeResponse(w, r, response)
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

		var request Request
		contentType, _, _ := mime.ParseMediaType(r.Header.Get("Content-Type"))
		switch contentType {
		case "application/json":
			if typ != "text" {
				unsupportedContentType(w, r)
				return
			}
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
				if typ != "text" {
					unsupportedContentType(w, r)
					return
				}
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
			Type:    typ,
			Content: request.Content,
			Errors:  make(map[string][]Error),
		}
		modTime := fileInfo.ModTime()
		if !modTime.IsZero() {
			response.ModTime = &modTime
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
