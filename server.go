package nb8

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"hash"
	"io"
	"io/fs"
	"log/slog"
	"net/http"
	"os"
	"path"
	"path/filepath"
	"strings"
	"time"

	"github.com/bokwoon95/sq"
	"github.com/caddyserver/certmagic"
	"github.com/klauspost/cpuid/v2"
	"github.com/mholt/acmez"
)

var defaultLogger = slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
	AddSource: true,
}))

func (nbrew *Notebrew) NewServer(dns01Solver acmez.Solver) (*http.Server, error) {
	server := &http.Server{
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
		IdleTimeout:  120 * time.Second,
		Addr:         nbrew.Domain,
		Handler:      nbrew,
	}
	if nbrew.Scheme != "https://" {
		return server, nil
	}
	if nbrew.Domain == "" {
		return nil, fmt.Errorf("Domain cannot be empty")
	}
	if nbrew.ContentDomain == "" {
		return nil, fmt.Errorf("ContentDomain cannot be empty")
	}
	server.Addr = ":443"
	domains := []string{nbrew.Domain}
	if nbrew.Domain == nbrew.ContentDomain {
		domains = append(domains, "www."+nbrew.Domain)
	} else {
		domains = append(domains, nbrew.ContentDomain, "www."+nbrew.ContentDomain)
	}
	// TODO: add this check into main, make this a panic instead and explictly
	// tell the user that it panics if a nil dns01 solver is passed in but the
	// multisite is subdomain.
	if nbrew.Multisite == "subdomain" {
		if certmagic.DefaultACME.CA == certmagic.LetsEncryptProductionCA && dns01Solver == nil {
			return nil, fmt.Errorf(`%s: "subdomain" not supported because DNS-01 solver not configured, please use "subdirectory" instead (more info: https://notebrew.com/path/to/docs/)`, filepath.Join("config/multisite.txt"))
		}
		domains = append(domains, "*."+nbrew.ContentDomain)
	}
	// certConfig manages the certificate for the admin domain, content domain
	// and wildcard subdomain.
	certConfig := certmagic.NewDefault()
	certConfig.Issuers = []certmagic.Issuer{
		// Create a new ACME issuer with the dns01Solver because this cert
		// config potentially has to issue wildcard certificates which only the
		// DNS-01 challenge solver is capable of.
		certmagic.NewACMEIssuer(certConfig, certmagic.ACMEIssuer{
			CA:          certmagic.DefaultACME.CA,
			TestCA:      certmagic.DefaultACME.TestCA,
			Logger:      certmagic.DefaultACME.Logger,
			HTTPProxy:   certmagic.DefaultACME.HTTPProxy,
			DNS01Solver: dns01Solver,
		}),
	}
	fmt.Printf("notebrew managing domains: %v\n", strings.Join(domains, ", "))
	err := certConfig.ManageSync(context.Background(), domains)
	if err != nil {
		return nil, err
	}
	// customDomainCertConfig manages the certificates for custom domains.
	customDomainCertConfig := certmagic.NewDefault()
	customDomainCertConfig.OnDemand = &certmagic.OnDemandConfig{
		DecisionFunc: func(name string) error {
			fileInfo, err := fs.Stat(nbrew.FS, name)
			if err != nil {
				return err
			}
			if !fileInfo.IsDir() {
				return fmt.Errorf("%q is not a directory", name)
			}
			if nbrew.DB == nil {
				return fmt.Errorf("database is nil")
			}
			exists, err := sq.FetchExists(nbrew.DB, sq.CustomQuery{
				Dialect: nbrew.Dialect,
				Format:  "SELECT 1 FROM site WHERE site_name = {name}",
				Values: []any{
					sq.StringParam("name", name),
				},
			})
			if err != nil {
				return err
			}
			if !exists {
				return fmt.Errorf("%q does not exist in site table", name)
			}
			return nil
		},
	}
	// Copied from (*certmagic.Config).TLSConfig().
	server.TLSConfig = &tls.Config{
		NextProtos: []string{"h2", "http/1.1", "acme-tls/1"},
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if clientHello.ServerName == "" {
				return nil, fmt.Errorf("clientHelloInfo.ServerName is empty")
			}
			for _, domain := range domains {
				if certmagic.MatchWildcard(clientHello.ServerName, domain) {
					return certConfig.GetCertificate(clientHello)
				}
			}
			return customDomainCertConfig.GetCertificate(clientHello)
		},
		MinVersion: tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
		PreferServerCipherSuites: true,
	}
	if cpuid.CPU.Supports(cpuid.AESNI) {
		server.TLSConfig.CipherSuites = []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
		}
	}
	return server, nil
}

func (nbrew *Notebrew) ServeHTTP(w http.ResponseWriter, r *http.Request) {
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

	// Inject the request method and url into the logger.
	logger := nbrew.Logger
	if logger == nil {
		logger = defaultLogger
	}
	scheme := "https://"
	if r.TLS == nil {
		scheme = "http://"
	}
	ip := getIP(r)
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
	if nbrew.Scheme == "https://" {
		w.Header().Add("Strict-Transport-Security", "max-age=63072000; includeSubDomains; preload")
	}

	segments := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if segments[0] == "admin" {
		switch strings.Trim(r.URL.Path, "/") {
		case "app.webmanifest":
			serveFile(w, r, rootFS, "static/app.webmanifest", false)
			return
		case "apple-touch-icon.png":
			serveFile(w, r, rootFS, "static/icons/apple-touch-icon.png", false)
			return
		}
	}

	host := getHost(r)
	urlPath := strings.Trim(r.URL.Path, "/")
	head, tail, _ := strings.Cut(urlPath, "/")
	if host == nbrew.Domain && head == "admin" {
		nbrew.admin(w, r, ip)
		return
	}

	var subdomainPrefix string
	var sitePrefix string
	var customDomain string
	if strings.HasSuffix(host, "."+nbrew.ContentDomain) {
		subdomainPrefix = strings.TrimSuffix(host, "."+nbrew.ContentDomain)
	} else if host != nbrew.ContentDomain {
		customDomain = host
	}
	if strings.HasPrefix(head, "@") {
		sitePrefix = head
	}
	if sitePrefix != "" && (subdomainPrefix != "" || customDomain != "") {
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}
	if sitePrefix != "" {
		urlPath = tail
		siteName := strings.TrimPrefix(sitePrefix, "@")
		for _, char := range siteName {
			if (char >= '0' && char <= '9') || (char >= 'a' && char <= 'z') || char == '-' {
				continue
			}
			http.Error(w, "404 Not Found", http.StatusNotFound)
			return
		}
		if siteName == "www" || nbrew.Multisite == "subdomain" {
			http.Redirect(w, r, nbrew.Scheme+siteName+"."+nbrew.ContentDomain+"/"+urlPath, http.StatusFound)
			return
		}
	} else if subdomainPrefix != "" {
		sitePrefix = "@" + subdomainPrefix
		for _, char := range subdomainPrefix {
			if (char >= '0' && char <= '9') || (char >= 'a' && char <= 'z') || char == '-' {
				continue
			}
			http.Error(w, "404 Not Found", http.StatusNotFound)
			return
		}
		if subdomainPrefix == "www" {
			sitePrefix = ""
		} else if nbrew.Multisite == "subdirectory" {
			http.Redirect(w, r, nbrew.Scheme+nbrew.ContentDomain+"/"+path.Join(sitePrefix, urlPath), http.StatusFound)
			return
		}
	} else if customDomain != "" {
		sitePrefix = customDomain
		fileInfo, err := fs.Stat(nbrew.FS, customDomain)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				http.Error(w, "404 Not Found", http.StatusNotFound)
				return
			}
			logger.Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		if !fileInfo.IsDir() {
			http.Error(w, "404 Not Found", http.StatusNotFound)
			return
		}
	}
	if nbrew.Multisite == "" && sitePrefix != "" {
		http.Error(w, "404 Not Found", http.StatusNotFound)
		return
	}

	custom404 := func(w http.ResponseWriter, r *http.Request, sitePrefix string) {
		file, err := nbrew.FS.Open(path.Join(sitePrefix, "output/themes/404.html"))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				http.Error(w, "404 Not Found", http.StatusNotFound)
				return
			}
			getLogger(r.Context()).Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		fileInfo, err := file.Stat()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		var b strings.Builder
		b.Grow(int(fileInfo.Size()))
		_, err = io.Copy(&b, file)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		templateParser, err := NewTemplateParser(r.Context(), nbrew, sitePrefix)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		tmpl, err := templateParser.Parse(b.String())
		if err != nil {
			http.Error(w, "404 Not Found\n"+err.Error(), http.StatusNotFound)
			return
		}
		w.WriteHeader(http.StatusNotFound)
		err = tmpl.Execute(w, nil)
		if err != nil {
			io.WriteString(w, err.Error())
		}
	}

	if r.Method != "GET" {
		http.Error(w, "405 Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	name := path.Join(sitePrefix, "output", urlPath)
	ext := path.Ext(name)
	if ext == "" {
		name = name + "/index.html"
		ext = ".html"
	}
	extInfo, ok := extensionInfo[ext]
	if !ok {
		custom404(w, r, sitePrefix)
		return
	}

	var isGzipped bool
	file, err := nbrew.FS.Open(name)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			getLogger(r.Context()).Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		if !extInfo.isGzippable {
			custom404(w, r, sitePrefix)
			return
		}
		file, err = nbrew.FS.Open(name + ".gz")
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				getLogger(r.Context()).Error(err.Error())
				http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
				return
			}
			custom404(w, r, sitePrefix)
			return
		}
		isGzipped = true
	}
	defer file.Close()

	fileInfo, err := file.Stat()
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
		return
	}
	if fileInfo.IsDir() {
		custom404(w, r, sitePrefix)
		return
	}

	if !extInfo.isGzippable {
		fileSeeker, ok := file.(io.ReadSeeker)
		if ok {
			http.ServeContent(w, r, name, fileInfo.ModTime(), fileSeeker)
			return
		}
		buf := bufPool.Get().(*bytes.Buffer)
		buf.Reset()
		defer bufPool.Put(buf)
		_, err = buf.ReadFrom(file)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		http.ServeContent(w, r, name, fileInfo.ModTime(), bytes.NewReader(buf.Bytes()))
		return
	}

	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	hasher := hashPool.Get().(hash.Hash)
	hasher.Reset()
	defer hashPool.Put(hasher)

	multiWriter := io.MultiWriter(buf, hasher)
	if isGzipped {
		_, err = io.Copy(multiWriter, file)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
	} else {
		gzipWriter := gzipPool.Get().(*gzip.Writer)
		gzipWriter.Reset(multiWriter)
		defer gzipPool.Put(gzipWriter)
		_, err = io.Copy(gzipWriter, file)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		err = gzipWriter.Close()
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
	}

	src := bytesPool.Get().(*[]byte)
	*src = (*src)[:0]
	defer bytesPool.Put(src)

	dst := bytesPool.Get().(*[]byte)
	*dst = (*dst)[:0]
	defer bytesPool.Put(dst)

	*src = hasher.Sum(*src)
	encodedLen := hex.EncodedLen(len(*src))
	if cap(*dst) < encodedLen {
		*dst = make([]byte, encodedLen)
	}
	*dst = (*dst)[:encodedLen]
	hex.Encode(*dst, *src)

	w.Header().Set("Content-Type", extInfo.contentType)
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("ETag", `"`+string(*dst)+`"`)
	http.ServeContent(w, r, name, fileInfo.ModTime(), bytes.NewReader(buf.Bytes()))
}

func serveFile(w http.ResponseWriter, r *http.Request, fsys fs.FS, name string, checkForGzipFallback bool) {
	if r.Method != "GET" {
		methodNotAllowed(w, r)
		return
	}

	var isGzippable bool
	ext := path.Ext(name)
	switch ext {
	// https://www.fastly.com/blog/new-gzip-settings-and-deciding-what-compress
	case ".html", ".css", ".js", ".md", ".txt", ".csv", ".tsv", ".json", ".xml", ".toml", ".yaml", ".yml", ".svg", ".ico", ".eot", ".otf", ".ttf":
		isGzippable = true
	case ".jpeg", ".jpg", ".png", ".gif", ".woff", ".woff2":
		isGzippable = false
	case ".webmanifest":
		isGzippable = true
	default:
		notFound(w, r)
		return
	}

	var isGzipped bool
	file, err := fsys.Open(name)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		if !isGzippable || !checkForGzipFallback {
			notFound(w, r)
			return
		}
		file, err = fsys.Open(name + ".gz")
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				getLogger(r.Context()).Error(err.Error())
				internalServerError(w, r, err)
				return
			}
			notFound(w, r)
			return
		}
		isGzipped = true
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

	if !isGzippable {
		fileSeeker, ok := file.(io.ReadSeeker)
		if ok {
			http.ServeContent(w, r, name, fileInfo.ModTime(), fileSeeker)
			return
		}
		buf := bufPool.Get().(*bytes.Buffer)
		buf.Reset()
		defer bufPool.Put(buf)
		_, err = buf.ReadFrom(file)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		http.ServeContent(w, r, name, fileInfo.ModTime(), bytes.NewReader(buf.Bytes()))
		return
	}

	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	hasher := hashPool.Get().(hash.Hash)
	hasher.Reset()
	defer hashPool.Put(hasher)

	multiWriter := io.MultiWriter(buf, hasher)
	if isGzipped {
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

	src := bytesPool.Get().(*[]byte)
	*src = (*src)[:0]
	defer bytesPool.Put(src)

	dst := bytesPool.Get().(*[]byte)
	*dst = (*dst)[:0]
	defer bytesPool.Put(dst)

	*src = hasher.Sum(*src)
	encodedLen := hex.EncodedLen(len(*src))
	if cap(*dst) < encodedLen {
		*dst = make([]byte, encodedLen)
	}
	*dst = (*dst)[:encodedLen]
	hex.Encode(*dst, *src)

	if ext == ".webmanifest" {
		w.Header().Set("Content-Type", "application/manifest+json")
	}
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("ETag", `"`+string(*dst)+`"`)
	http.ServeContent(w, r, name, fileInfo.ModTime(), bytes.NewReader(buf.Bytes()))
}

var extensionInfo = map[string]struct {
	contentType string
	isGzippable bool
}{
	".html":  {"text/html", true},
	".css":   {"text/css", true},
	".js":    {"text/javascript", true},
	".md":    {"text/markdown", true},
	".txt":   {"text/plain", true},
	".csv":   {"text/csv", true},
	".tsv":   {"text/tsv", true},
	".json":  {"application/json", true},
	".xml":   {"application/xml", true},
	".toml":  {"application/toml", true},
	".yaml":  {"application/yaml", true},
	".svg":   {"image/svg", true},
	".ico":   {"image/ico", true},
	".jpeg":  {"image/jpeg", false},
	".jpg":   {"image/jpeg", false},
	".png":   {"image/png", false},
	".gif":   {"image/gif", false},
	".eot":   {"font/eot", false},
	".otf":   {"font/otf", false},
	".ttf":   {"font/ttf", false},
	".woff":  {"font/woff", false},
	".woff2": {"font/woff2", false},
	".gzip":  {"application/gzip", false},
	".gz":    {"application/gzip", false},
}

func (nbrew *Notebrew) admin(w http.ResponseWriter, r *http.Request, ip string) {
	urlPath := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin"), "/")
	head, tail, _ := strings.Cut(urlPath, "/")
	if head == "static" {
		serveFile(w, r, rootFS, urlPath, true)
		return
	}
	if head == "signup" || head == "login" || head == "logout" || head == "resetpassword" {
		if tail != "" {
			notFound(w, r)
			return
		}
		switch head {
		case "signup":
			nbrew.signup(w, r, ip)
		case "login":
			nbrew.login(w, r, ip)
		case "logout":
			nbrew.logout(w, r, ip)
		}
		return
	}

	var sitePrefix string
	if strings.HasPrefix(head, "@") || strings.Contains(head, ".") {
		sitePrefix, urlPath = head, tail
		head, tail, _ = strings.Cut(urlPath, "/")
	}

	if head == "themes" || head == "images" {
		serveFile(w, r, nbrew.FS, path.Join(sitePrefix, "output", urlPath), true)
		return
	}

	var username string
	if nbrew.DB != nil {
		authenticationTokenHash := getAuthenticationTokenHash(r)
		if authenticationTokenHash == nil {
			if head == "" {
				http.Redirect(w, r, nbrew.Scheme+nbrew.Domain+"/admin/login/?401", http.StatusFound)
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
				" WHERE authentication.authentication_token_hash = {authenticationTokenHash}" +
				" LIMIT 1",
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
					http.Redirect(w, r, nbrew.Scheme+nbrew.Domain+"/admin/login/?401", http.StatusFound)
					return
				}
				notAuthenticated(w, r)
				return
			}
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		username = result.Username
		logger := getLogger(r.Context()).With(slog.String("username", username))
		r = r.WithContext(context.WithValue(r.Context(), loggerKey, logger))
		if !result.IsAuthorized {
			if (sitePrefix != "" || head != "") && head != "createsite" && head != "deletesite" {
				notAuthorized(w, r)
				return
			}
		}
	}

	if head == "" || head == "notes" || head == "output" || head == "pages" || head == "posts" {
		fileInfo, err := fs.Stat(nbrew.FS, path.Join(sitePrefix, urlPath))
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) {
				notFound(w, r)
				return
			}
			getLogger(r.Context()).Error(err.Error())
			internalServerError(w, r, err)
			return
		}
		if fileInfo.IsDir() {
			nbrew.folder(w, r, username, sitePrefix, urlPath, fileInfo)
			return
		}
		nbrew.file(w, r, username, sitePrefix, urlPath, fileInfo)
		return
	}

	if tail != "" {
		notFound(w, r)
		return
	}
	switch head {
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
}