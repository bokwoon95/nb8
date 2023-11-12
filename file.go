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

func (nbrew *Notebrew) file(w http.ResponseWriter, r *http.Request, username, sitePrefix, filePath string, fileInfo fs.FileInfo) {
	type Request struct {
		Content string `json:"content"`
	}
	type Response struct {
		Status         Error      `json:"status"`
		ContentDomain  string     `json:"contentDomain,omitempty"`
		Username       string     `json:"username,omitempty"`
		SitePrefix     string     `json:"sitePrefix,omitempty"`
		Path           string     `json:"path"`
		IsDir          bool       `json:"isDir,omitempty"`
		ModTime        *time.Time `json:"modTime,omitempty"`
		Content        string     `json:"content,omitempty"`
		Size           int64      `json:"size,omitempty"`
		TemplateErrors []string   `json:"templateErrors,omitempty"`
	}
	fileType, ok := fileTypes[path.Ext(filePath)]
	if !ok {
		notFound(w, r)
		return
	}
	segments := strings.Split(filePath, "/")
	isEditableText := false
	switch fileType.Ext {
	case ".html", ".css", ".js", ".md", ".txt":
		if segments[0] != "output" || (len(segments) > 1 && segments[1] == "themes") {
			isEditableText = true
		}
	}

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
			if !isEditableText {
				// TODO: serveFile
			}
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
		response.Size = fileInfo.Size()
		modTime := fileInfo.ModTime()
		if !modTime.IsZero() {
			response.ModTime = &modTime
		}
		if response.Status != "" {
			writeResponse(w, r, response)
			return
		}
		// TODO: if fileType.Ext one of .html .css .js .md .txt, read the file. Else, serve the file
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
		if !isEditableText {
		}
		// would you allow updating non-text files?

		var request Request
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
			Content: request.Content,
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
