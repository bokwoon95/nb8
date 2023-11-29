package nb8

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"encoding/hex"
	"errors"
	"hash"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"path"
	"strings"
	"time"

	"github.com/bokwoon95/sq"
	"github.com/caddyserver/certmagic"
)

func (nbrew *Notebrew) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Redirect the www subdomain to the bare domain.
	if r.Host == "www."+nbrew.Domain {
		if nbrew.Domain == "localhost" || strings.HasPrefix(nbrew.Domain, "localhost:") {
			http.Redirect(w, r, "http://"+nbrew.Domain+r.URL.RequestURI(), http.StatusMovedPermanently)
			return
		}
		http.Redirect(w, r, "https://"+nbrew.Domain+r.URL.RequestURI(), http.StatusMovedPermanently)
		return
	}

	// Clean the path and redirect if necessary.
	if r.Method == "GET" {
		cleanedPath := path.Clean(r.URL.Path)
		if cleanedPath != "/" && path.Ext(cleanedPath) == "" {
			cleanedPath += "/"
		}
		if cleanedPath != r.URL.Path {
			cleanedURL := *r.URL
			cleanedURL.Path = cleanedPath
			http.Redirect(w, r, cleanedURL.String(), http.StatusMovedPermanently)
			return
		}
	}

	// Add request method, url and ip to the logger.
	logger := *nbrew.Logger.Load()
	if logger == nil {
		logger = slog.Default()
	}
	scheme := "https://"
	if r.TLS == nil {
		scheme = "http://"
	}
	ip := nbrew.realClientIP(r)
	logger = logger.With(
		slog.String("method", r.Method),
		slog.String("url", scheme+r.Host+r.URL.RequestURI()),
		slog.String("ip", ip),
	)
	r = r.WithContext(context.WithValue(r.Context(), loggerKey, logger))

	// https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html
	w.Header().Add("X-Frame-Options", "DENY")
	w.Header().Add("X-Content-Type-Options", "nosniff")
	w.Header().Add("Referrer-Policy", "strict-origin-when-cross-origin")
	w.Header().Add("Permissions-Policy", "geolocation=(), camera=(), microphone=()")
	w.Header().Add("Cross-Origin-Opener-Policy", "same-origin")
	w.Header().Add("Cross-Origin-Embedder-Policy", "require-corp")
	w.Header().Add("Cross-Origin-Resource-Policy", "same-origin")
	if nbrew.Domain != "localhost" && !strings.HasPrefix(nbrew.Domain, "localhost:") {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
	}

	// Special case: make these files available on the root path of the main
	// domain.
	if r.Host == nbrew.Domain {
		switch strings.Trim(r.URL.Path, "/") {
		case "app.webmanifest":
			w.Header().Add("Cache-Control", "max-age: 2592000, stale-while-revalidate" /* 1 month */)
			serveFile(w, r, rootFS, "static/app.webmanifest")
			return
		case "apple-touch-icon.png":
			w.Header().Add("Cache-Control", "max-age: 2592000, stale-while-revalidate" /* 1 month */)
			serveFile(w, r, rootFS, "static/icons/apple-touch-icon.png")
			return
		}
	}

	urlPath := strings.Trim(r.URL.Path, "/")
	ext := path.Ext(urlPath)
	head, tail, _ := strings.Cut(urlPath, "/")

	// Handle the /users/* route on the main domain.
	if r.Host == nbrew.Domain && head == "users" {
		switch tail {
		case "signup":
			nbrew.signup(w, r, ip)
		case "login":
			nbrew.login(w, r, ip)
		case "logout":
			nbrew.logout(w, r, ip)
		case "resetpassword":
		default:
			notFound(w, r)
		}
		return
	}

	// Handle the /files/* route on the main domain.
	if r.Host == nbrew.Domain && head == "files" {
		urlPath := tail
		head, tail, _ := strings.Cut(urlPath, "/")
		if head == "static" {
			w.Header().Add("Cache-Control", "max-age: 31536000, stale-while-revalidate" /* 1 year */)
			serveFile(w, r, rootFS, urlPath)
			return
		}

		// Figure out the sitePrefix of the site we are serving.
		var sitePrefix string
		if strings.HasPrefix(head, "@") || strings.Contains(head, ".") {
			sitePrefix, urlPath = head, tail
			head, tail, _ = strings.Cut(urlPath, "/")
		}

		// If the database is present, check if the user is authorized to
		// access the files for this site.
		var username string
		if nbrew.DB != nil {
			authenticationTokenHash := getAuthenticationTokenHash(r)
			if authenticationTokenHash == nil {
				if head == "" {
					http.Redirect(w, r, "/users/login/?401", http.StatusFound)
					return
				}
				notAuthenticated(w, r)
				return
			}
			result, err := sq.FetchOneContext(r.Context(), nbrew.DB, sq.CustomQuery{
				Dialect: nbrew.Dialect,
				Format: "SELECT {*}" +
					" FROM authentication" +
					" JOIN users ON users.user_id = authentication.user_id" +
					" LEFT JOIN (" +
					"SELECT site_user.user_id" +
					" FROM site_user" +
					" JOIN site ON site.site_id = site_user.site_id" +
					" WHERE site.site_name = {siteName}" +
					") AS authorized_users ON authorized_users.user_id = users.user_id" +
					" WHERE authentication.authentication_token_hash = {authenticationTokenHash}",
				Values: []any{
					sq.StringParam("siteName", strings.TrimPrefix(sitePrefix, "@")),
					sq.BytesParam("authenticationTokenHash", authenticationTokenHash),
				},
			}, func(row *sq.Row) (result struct {
				Username     string
				IsAuthorized bool
			}) {
				result.Username = row.String("users.username")
				result.IsAuthorized = row.Bool("authorized_users.user_id IS NOT NULL")
				return result
			})
			if err != nil {
				if errors.Is(err, sql.ErrNoRows) {
					http.SetCookie(w, &http.Cookie{
						Path:   "/",
						Name:   "authentication",
						Value:  "0",
						MaxAge: -1,
					})
					if head == "" {
						http.Redirect(w, r, "/users/login/?401", http.StatusFound)
						return
					}
					notAuthenticated(w, r)
					return
				}
				logger.Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			username = result.Username
			logger := logger.With(slog.String("username", username))
			r = r.WithContext(context.WithValue(r.Context(), loggerKey, logger))
			if !result.IsAuthorized {
				if sitePrefix != "" {
					notAuthorized(w, r)
					return
				}
				// If the current sitePrefix is empty, the user needs access to
				// the following URL paths unconditionally:
				//
				// 1. <empty> (needed to switch between their sites)
				//
				// 2. createsite (needed to create a new site)
				//
				// 3. deletesite (needed to delete their sites)
				//
				// If not any of the three, then notAuthorized.
				if urlPath != "" && urlPath != "createsite" && urlPath != "deletesite" {
					notAuthorized(w, r)
					return
				}
			}
		}

		switch head {
		case "", "notes", "pages", "posts", "output":
			fileInfo, err := fs.Stat(nbrew.FS, path.Join(".", sitePrefix, urlPath))
			if err != nil {
				if errors.Is(err, fs.ErrNotExist) {
					notFound(w, r)
					return
				}
				logger.Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			if fileInfo.IsDir() {
				nbrew.folder(w, r, username, sitePrefix, urlPath, fileInfo)
				return
			}
			nbrew.file(w, r, username, sitePrefix, urlPath, fileInfo)
			return
		default:
			switch urlPath {
			case "createsite":
			case "deletesite":
			case "delete":
			case "createnote":
			case "createpost":
			case "createcategory":
			case "createfolder":
			case "createpage":
			case "createfile":
			case "cut":
			case "copy":
			case "paste":
			case "rename":
			default:
				notFound(w, r)
			}
			return
		}
	}

	// If we reach here, we are serving pregenerated site content. Only GET
	// requests are allowed.
	if r.Method != "GET" {
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	// Figure out the sitePrefix of the site we have to serve.
	var sitePrefix string
	if certmagic.MatchWildcard(r.Host, "*."+nbrew.ContentDomain) {
		subdomain := strings.TrimSuffix(r.Host, "."+nbrew.ContentDomain)
		switch subdomain {
		case "cdn", "www":
			// examples:
			// cdn.nbrew.io/foo/bar.jpg             => sitePrefix: <none>,      urlPath: foo/bar.jpg
			// cdn.nbrew.io/@username/foo/bar.jpg   => sitePrefix: @username,   urlPath: foo/bar.jpg
			// cdn.nbrew.io/example.com/foo/bar.jpg => sitePrefix: example.com, urlPath: foo/bar.jpg
			if strings.HasPrefix(head, "@") {
				sitePrefix, urlPath = head, tail
			} else if strings.Contains(head, ".") {
				if tail != "" {
					sitePrefix, urlPath = head, tail
				} else {
					_, ok := fileTypes[path.Ext(head)] // differentiate between file extension and TLD
					if !ok {
						sitePrefix, urlPath = head, tail
					}
				}
			}
			// TODO: if we don't set CORS on the www subdomain, can't users
			// just bypass the CORS restrictions on the cdn subdomain by
			// visiting the www subdomain instead? Another thing, do we really
			// want the public to be able to embed our resources on their web
			// pages? Is it possible to whitelist the CDN server in ConfigFS
			// such that we only Access-Control-Allow-Origin if the person
			// knocking on the www subdomain is the CDN service? Think this
			// through (needs more testing).
			if subdomain == "cdn" {
				w.Header().Set("Access-Control-Allow-Origin", "*")
				w.Header().Set("Access-Control-Allow-Methods", "GET")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
			}
		default:
			sitePrefix = "@" + subdomain
		}
	} else if r.Host != nbrew.ContentDomain {
		sitePrefix = r.Host
	}

	var fileType FileType
	var isGzipped bool
	var modTime time.Time
	// fileSrc may be an fs.File or a bufio.Reader.
	var fileSrc io.Reader
	basename := path.Base(urlPath)
	if ext == "" || basename == "atom.xml" {
		var name string
		if basename == "atom.xml" {
			name = path.Join(sitePrefix, "output", urlPath)
			fileType.Ext = ".xml"
			// Despite atom's Content-Type technically being
			// application/atom+xml, I'm using application/xml here otherwise
			// iOS Safari "helpfully" prompts the user to install an RSS reader
			// from the App Store and *refuses* to display the Atom feed
			// contents in the browser. I'm annoyed by that. Atom feeds are
			// just plain text, let me view in the the browser. Every RSS
			// reader worth its salt can handle an incorrect Content-Type so
			// I'll rather use an incorrect Content-Type and force Safari to
			// render the atom feed in plain text than prevent the feed from
			// being viewed in the browser for the sake of "technical purity".
			fileType.ContentType = "application/xml; charset=utf-8"
			fileType.IsGzippable = true
		} else {
			// If the URL has no extension, we serve index.html.
			name = path.Join(sitePrefix, "output", urlPath, "index.html")
			fileType.Ext = ".html"
			fileType.ContentType = "text/html; charset=utf-8"
			fileType.IsGzippable = true
		}
		file, err := nbrew.FS.Open(name)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				nbrew.site404(w, r, sitePrefix)
				return
			}
			logger.Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		defer file.Close()
		fileInfo, err := file.Stat()
		if err != nil {
			logger.Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		if fileInfo.IsDir() {
			nbrew.site404(w, r, sitePrefix)
			return
		}
		// The file may have been gzipped (to save space). Peek the first 512
		// bytes and check if it is gzipped.
		reader := readerPool.Get().(*bufio.Reader)
		reader.Reset(file)
		defer readerPool.Put(reader)
		b, err := reader.Peek(512)
		if err != nil && err != io.EOF {
			logger.Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		contentType := http.DetectContentType(b)
		isGzipped = contentType == "application/x-gzip" || contentType == "application/gzip"
		modTime = fileInfo.ModTime()
		fileSrc = reader
	} else {
		// Else if the URL has an extension, serve the file based on the
		// file extension.
		fileType = fileTypes[ext]
		if fileType == (FileType{}) {
			nbrew.site404(w, r, sitePrefix)
			return
		}
		// Special case: display all .html files as plaintext so that their raw
		// contents are shown instead of being rendered by the browser (normal
		// HTML pages have extensionless URLs, handled above).
		if fileType.Ext == ".html" {
			fileType.ContentType = "text/plain; charset=utf-8"
		}
		file, err := nbrew.FS.Open(path.Join(sitePrefix, "output", urlPath))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				nbrew.site404(w, r, sitePrefix)
				return
			}
			logger.Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		defer file.Close()
		fileInfo, err := file.Stat()
		if err != nil {
			logger.Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		// If the file is too big, stream it out to the user instead of
		// buffering it in memory. This means we won't be able to calculate its
		// ETag, but that's the tradeoff.
		if fileInfo.Size() > 15<<20 /* 15MB */ {
			w.Header().Set("Content-Type", fileType.ContentType)
			_, err := io.Copy(w, file)
			if err != nil {
				logger.Error(err.Error())
				return
			}
			return
		}
		modTime = fileInfo.ModTime()
		fileSrc = file
	}

	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	hasher := hashPool.Get().(hash.Hash)
	hasher.Reset()
	defer hashPool.Put(hasher)

	// NOTE: we may eventually encounter clients that don't understand gzip,
	// e.g. RSS client applications that cannot read a gzipped atom.xml. Do we
	// care about them? All browsers accept gzip so index.html should be fine.

	// Gzip the file data into a buffer and hasher to calulate its ETag hash.
	// If the file cannot be gzipped or is already gzipped, skip the gzipping
	// step.
	multiWriter := io.MultiWriter(buf, hasher)
	if !fileType.IsGzippable || isGzipped {
		_, err := io.Copy(multiWriter, fileSrc)
		if err != nil {
			logger.Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
	} else {
		gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
		gzipWriter.Reset(multiWriter)
		defer gzipWriterPool.Put(gzipWriter)
		_, err := io.Copy(gzipWriter, fileSrc)
		if err != nil {
			logger.Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		err = gzipWriter.Close()
		if err != nil {
			logger.Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		isGzipped = true
	}

	b := bytesPool.Get().(*[]byte)
	*b = (*b)[:0]
	defer bytesPool.Put(b)

	if isGzipped {
		w.Header().Set("Content-Encoding", "gzip")
	}
	w.Header().Set("Content-Type", fileType.ContentType)
	w.Header().Set("Cache-Control", "no-cache, must-revalidate")
	w.Header().Set("ETag", `"`+hex.EncodeToString(hasher.Sum(*b))+`"`)
	http.ServeContent(w, r, "", modTime, bytes.NewReader(buf.Bytes()))
}

// site404 is a 404 handler that will use the site's 404 page if present,
// otherwise it falls back to http.Error().
//
// We fall back to http.Error() instead of notFound() because notFound()
// depends on CSS/JS files hosted on the main domain and we don't want that
// dependency.
func (nbrew *Notebrew) site404(w http.ResponseWriter, r *http.Request, sitePrefix string) {
	// Check if the user's custom 404 page is available.
	file, err := nbrew.FS.Open(path.Join(sitePrefix, "output/404/index.html"))
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			getLogger(r.Context()).Error(err.Error())
		}
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}
	fileInfo, err := file.Stat()
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}

	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	hasher := hashPool.Get().(hash.Hash)
	hasher.Reset()
	defer hashPool.Put(hasher)

	reader := readerPool.Get().(*bufio.Reader)
	reader.Reset(file)
	defer readerPool.Put(reader)

	// Peek the first 512 bytes to check if 404/index.html is gzipped and
	// write it into the buffer + ETag hasher accordingly. The buffer
	// always receives gzipped data, the only difference is whether the
	// data has been pre-gzipped or not.
	b, err := reader.Peek(512)
	if err != nil && err != io.EOF {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}
	// NOTE: do we want to calculate ETags for 404 pages? Do we want to cache
	// the 404 response? Are we expecting users to hit 404 pages often?
	contentType := http.DetectContentType(b)
	multiWriter := io.MultiWriter(buf, hasher)
	if contentType == "application/x-gzip" || contentType == "application/gzip" {
		_, err := io.Copy(multiWriter, reader)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			http.Error(w, "404 Not Found", http.StatusNotFound)
			return
		}
	} else {
		gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
		gzipWriter.Reset(multiWriter)
		defer gzipWriterPool.Put(gzipWriter)
		_, err := io.Copy(gzipWriter, reader)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			http.Error(w, "404 Not Found", http.StatusNotFound)
			return
		}
		err = gzipWriter.Close()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			http.Error(w, "404 Not Found", http.StatusNotFound)
			return
		}
	}

	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("ETag", `"`+hex.EncodeToString(hasher.Sum(b[:0]))+`"`)
	w.WriteHeader(http.StatusNotFound)
	http.ServeContent(w, r, "", fileInfo.ModTime(), bytes.NewReader(buf.Bytes()))
}
