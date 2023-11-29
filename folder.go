package nb8

import (
	"encoding/json"
	"errors"
	"html/template"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/bokwoon95/sq"
)

// TODO: eventually we'll have to do the big headache of adding pagination
// through interface discovery (which also requires figuring out how sorting
// would work).
func (nbrew *Notebrew) folder(w http.ResponseWriter, r *http.Request, username, sitePrefix, folderPath string, fileInfo fs.FileInfo) {
	type FileEntry struct {
		Name    string    `json:"name,omitempty"`
		IsDir   bool      `json:"isDir,omitempty"`
		IsSite  bool      `json:"isSite,omitempty"`
		IsUser  bool      `json:"isUser,omitempty"`
		Size    int64     `json:"size,omitempty"`
		ModTime time.Time `json:"modTime,omitempty"`
	}
	type Response struct {
		Status         Error       `json:"status"`
		ContentDomain  string      `json:"contentDomain,omitempty"`
		Username       string      `json:"username,omitempty"`
		SitePrefix     string      `json:"sitePrefix,omitempty"`
		Path           string      `json:"path"`
		IsDir          bool        `json:"isDir,omitempty"`
		ModTime        time.Time   `json:"modTime,omitempty"`
		FileEntries    []FileEntry `json:"fileEntries,omitempty"`
		TemplateErrors []string    `json:"templateErrors,omitempty"`
	}
	if r.Method != "GET" {
		methodNotAllowed(w, r)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, 2<<20 /* 2MB */)
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
	response.Path = folderPath
	response.IsDir = fileInfo.IsDir()
	if response.Status == "" {
		response.Status = Success
	}

	var authorizedForRootSite bool
	if folderPath == "" {
		for _, name := range []string{"notes", "pages", "posts", "output/themes", "output"} {
			fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, name))
			if err != nil {
				if !errors.Is(err, fs.ErrNotExist) {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
			} else if fileInfo.IsDir() {
				fileEntry := FileEntry{
					Name:    name,
					IsDir:   true,
					ModTime: fileInfo.ModTime(),
				}
				response.FileEntries = append(response.FileEntries, fileEntry)
			}
		}
		if sitePrefix == "" {
			if nbrew.DB != nil {
				results, err := sq.FetchAllContext(r.Context(), nbrew.DB, sq.CustomQuery{
					Dialect: nbrew.Dialect,
					Format: "SELECT {*}" +
						" FROM site" +
						" JOIN site_user ON site_user.site_id = site.site_id" +
						" JOIN users ON users.user_id = site_user.user_id" +
						" WHERE users.username = {username}" +
						" ORDER BY site_prefix",
					Values: []any{
						sq.StringParam("username", username),
					},
				}, func(row *sq.Row) (result struct {
					SitePrefix string
					IsUser     bool
				}) {
					result.SitePrefix = row.String("CASE" +
						" WHEN site.site_name LIKE '%.%' THEN site.site_name" +
						" WHEN site.site_name <> '' THEN '@' || site.site_name" +
						" ELSE ''" +
						" END AS site_prefix",
					)
					result.IsUser = row.Bool("EXISTS (SELECT 1 FROM users WHERE users.username = site.site_name)")
					return result
				})
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				for _, result := range results {
					if result.SitePrefix == "" {
						authorizedForRootSite = true
						continue
					}
					fileInfo, err := fs.Stat(nbrew.FS, path.Join(".", result.SitePrefix))
					if err != nil {
						if !errors.Is(err, fs.ErrNotExist) {
							getLogger(r.Context()).Error(err.Error())
							internalServerError(w, r, err)
							return
						}
					} else if fileInfo.IsDir() {
						response.FileEntries = append(response.FileEntries, FileEntry{
							Name:   result.SitePrefix,
							IsDir:  true,
							IsSite: true,
							IsUser: result.IsUser,
						})
					}
				}
				if !authorizedForRootSite {
					n := 0
					for _, fileEntry := range response.FileEntries {
						switch fileEntry.Name {
						case "notes", "pages", "posts", "output/themes", "output":
							continue
						default:
							response.FileEntries[n] = fileEntry
							n++
						}
					}
					response.FileEntries = response.FileEntries[:n]
				}
			} else {
				authorizedForRootSite = true
				dirEntries, err := nbrew.FS.ReadDir(".")
				if err != nil {
					getLogger(r.Context()).Error(err.Error())
					internalServerError(w, r, err)
					return
				}
				for _, dirEntry := range dirEntries {
					if !dirEntry.IsDir() {
						continue
					}
					name := dirEntry.Name()
					if !strings.Contains(name, ".") && !strings.HasPrefix(name, "@") {
						continue
					}
					response.FileEntries = append(response.FileEntries, FileEntry{
						Name:   name,
						IsDir:  true,
						IsSite: true,
					})
				}
			}
		}
	} else {
		head, _, _ := strings.Cut(folderPath, "/")
		if head != "notes" && head != "pages" && head != "posts" && head != "output" {
			notFound(w, r)
			return
		}
		dirEntries, err := nbrew.FS.ReadDir(path.Join(sitePrefix, folderPath))
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		for _, dirEntry := range dirEntries {
			fileInfo, err := dirEntry.Info()
			if err != nil {
				getLogger(r.Context()).Error(err.Error(), slog.String("name", dirEntry.Name()))
				internalServerError(w, r, err)
				return
			}
			fileEntry := FileEntry{
				Name:    dirEntry.Name(),
				IsDir:   dirEntry.IsDir(),
				Size:    fileInfo.Size(),
				ModTime: fileInfo.ModTime(),
			}
			ext := path.Ext(fileEntry.Name)
			switch head {
			case "notes", "output":
				if fileEntry.IsDir {
					response.FileEntries = append(response.FileEntries, fileEntry)
					continue
				}
				fileType := fileTypes[ext]
				if !strings.HasPrefix(fileType.ContentType, "text") && !strings.HasPrefix(fileType.ContentType, "image") {
					continue
				}
				response.FileEntries = append(response.FileEntries, fileEntry)
			case "pages":
				if fileEntry.IsDir {
					response.FileEntries = append(response.FileEntries, fileEntry)
					continue
				}
				if ext != ".html" {
					continue
				}
				response.FileEntries = append(response.FileEntries, fileEntry)
			case "posts":
				if fileEntry.IsDir {
					if strings.Contains(folderPath, "/") {
						continue
					}
					response.FileEntries = append(response.FileEntries, fileEntry)
					continue
				}
				if ext != ".md" {
					continue
				}
				response.FileEntries = append(response.FileEntries, fileEntry)
			}
		}
	}

	if r.Form.Has("api") {
		w.Header().Set("Content-Type", "application/json")
		encoder := json.NewEncoder(w)
		encoder.SetEscapeHTML(false)
		err := encoder.Encode(&response)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
		}
		return
	}

	contentURL := nbrew.contentURL(sitePrefix)
	funcMap := map[string]any{
		"join":                  path.Join,
		"base":                  path.Base,
		"ext":                   path.Ext,
		"hasPrefix":             strings.HasPrefix,
		"trimPrefix":            strings.TrimPrefix,
		"contains":              strings.Contains,
		"fileSizeToString":      fileSizeToString,
		"stylesCSS":             func() template.CSS { return template.CSS(stylesCSS) },
		"folderJS":              func() template.JS { return template.JS(folderJS) },
		"contentURL":            func() string { return contentURL },
		"hasDatabase":           func() bool { return nbrew.DB != nil },
		"referer":               func() string { return r.Referer() },
		"safeHTML":              func(s string) template.HTML { return template.HTML(s) },
		"authorizedForRootSite": func() bool { return authorizedForRootSite },
		"head": func(s string) string {
			head, _, _ := strings.Cut(s, "/")
			return head
		},
		"tail": func(s string) string {
			_, tail, _ := strings.Cut(s, "/")
			return tail
		},
		"generateBreadcrumbLinks": func(filePath string) template.HTML {
			var b strings.Builder
			b.WriteString(`<a href="/files/">files</a>`)
			segments := strings.Split(filePath, "/")
			if sitePrefix != "" {
				segments = append([]string{sitePrefix}, segments...)
			}
			for i := 0; i < len(segments); i++ {
				if segments[i] == "" {
					continue
				}
				href := `/files/` + path.Join(segments[:i+1]...) + `/`
				if i == len(segments)-1 && !response.IsDir {
					href = strings.TrimSuffix(href, `/`)
				}
				b.WriteString(` / <a href="` + href + `">` + segments[i] + `</a>`)
			}
			if response.IsDir {
				b.WriteString(` /`)
			}
			return template.HTML(b.String())
		},
	}
	tmpl, err := template.New("folder.html").Funcs(funcMap).ParseFS(rootFS, "embed/folder.html")
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		internalServerError(w, r, err)
		return
	}
	// https://cdn.{{ $.ContentDomain }}/{{ join $.SitePrefix $.Parent $.Name }}
	contentSecurityPolicy(w, "", false)
	executeTemplate(w, r, fileInfo.ModTime(), tmpl, &response)
}
