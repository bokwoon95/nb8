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
	"path"
	"strings"
	"time"

	"github.com/bokwoon95/sq"
	"github.com/caddyserver/certmagic"
	"github.com/klauspost/cpuid/v2"
	"github.com/mholt/acmez"
)

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
	var domains []string
	if nbrew.Domain == nbrew.ContentDomain {
		domains = []string{
			nbrew.Domain,
			"www." + nbrew.Domain,
			"cdn." + nbrew.Domain,
			"assets." + nbrew.Domain,
		}
	} else {
		domains = []string{
			nbrew.Domain,
			nbrew.ContentDomain,
			"www." + nbrew.Domain,
			"www." + nbrew.ContentDomain,
			"cdn." + nbrew.ContentDomain,
			"assets." + nbrew.ContentDomain,
		}
	}
	if dns01Solver != nil {
		domains = append(domains, "*."+nbrew.ContentDomain)
	}
	// staticCertConfig manages the certificate for the admin domain, content domain
	// and wildcard subdomain.
	staticCertConfig := certmagic.NewDefault()
	staticCertConfig.Issuers = []certmagic.Issuer{
		// Create a new ACME issuer with the dns01Solver because this cert
		// config potentially has to issue wildcard certificates which only the
		// DNS-01 challenge solver is capable of.
		certmagic.NewACMEIssuer(staticCertConfig, certmagic.ACMEIssuer{
			CA:          certmagic.DefaultACME.CA,
			TestCA:      certmagic.DefaultACME.TestCA,
			Logger:      certmagic.DefaultACME.Logger,
			HTTPProxy:   certmagic.DefaultACME.HTTPProxy,
			DNS01Solver: dns01Solver,
		}),
	}
	fmt.Printf("notebrew static domains: %v\n", strings.Join(domains, ", "))
	err := staticCertConfig.ManageSync(context.Background(), domains)
	if err != nil {
		return nil, err
	}
	// dynamicCertConfig manages the certificates for custom domains.
	//
	// If dns01Solver hasn't been configured, dynamicCertConfig will also be
	// responsible for getting the certificates for subdomains. This approach
	// will not scale and may exceed the rate limits of Let's Encrypt (50
	// certificates per week, a certificate lasts for 3 months). The safest way
	// is to configure dns01Solver so that the wildcard certificate is
	// available.
	dynamicCertConfig := certmagic.NewDefault()
	dynamicCertConfig.OnDemand = &certmagic.OnDemandConfig{
		DecisionFunc: func(name string) error {
			if certmagic.MatchWildcard(name, "*."+nbrew.ContentDomain) {
				return nil
			}
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
				return nil, fmt.Errorf("clientHello.ServerName is empty")
			}
			for _, domain := range domains {
				if certmagic.MatchWildcard(clientHello.ServerName, domain) {
					return staticCertConfig.GetCertificate(clientHello)
				}
			}
			return dynamicCertConfig.GetCertificate(clientHello)
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
		logger = slog.Default()
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
			serveFile(w, r, rootFS, "static/app.webmanifest")
			return
		case "apple-touch-icon.png":
			serveFile(w, r, rootFS, "static/icons/apple-touch-icon.png")
			return
		}
	}

	host := getHost(r)
	if host == "www."+nbrew.Domain {
		http.Redirect(w, r, nbrew.Scheme+nbrew.Domain+r.URL.RequestURI(), http.StatusMovedPermanently)
		return
	}
	if host == "www."+nbrew.ContentDomain {
		http.Redirect(w, r, nbrew.Scheme+nbrew.ContentDomain+r.URL.RequestURI(), http.StatusMovedPermanently)
		return
	}

	urlPath := strings.Trim(r.URL.Path, "/")
	head, tail, _ := strings.Cut(urlPath, "/")
	if host == nbrew.Domain && head == "admin" {
		nbrew.admin(w, r, ip)
		return
	}

	var sitePrefix string
	if certmagic.MatchWildcard(host, "*."+nbrew.ContentDomain) {
		subdomain := strings.TrimSuffix(host, "."+nbrew.ContentDomain)
		switch subdomain {
		case "cdn", "assets":
			if path.Ext(urlPath) == "" {
				http.Error(w, "404 Not Found", http.StatusNotFound)
				return
			}
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
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		default:
			sitePrefix = "@" + subdomain
		}
	} else if host != nbrew.ContentDomain {
		sitePrefix = host
	}

	// custom404 will use the user's custom 404 page if present, otherwise it
	// will fall back to http.Error(404). We don't use notFound() because it
	// depends on static files in the main domain and the content domain should
	// not depend on the main domain.
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
	if path.Ext(name) == "" {
		name = name + "/index.html"
	}
	fileType, ok := fileTypes[path.Ext(name)]
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
		if !fileType.IsGzippable || !strings.HasSuffix(name, "/index.html") {
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

	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	hasher := hashPool.Get().(hash.Hash)
	hasher.Reset()
	defer hashPool.Put(hasher)

	if !fileType.IsGzippable {
		fileSeeker, ok := file.(io.ReadSeeker)
		if ok {
			http.ServeContent(w, r, name, fileInfo.ModTime(), fileSeeker)
			return
		}
		_, err = buf.ReadFrom(file)
		if err != nil {
			getLogger(r.Context()).Error(err.Error())
			http.Error(w, "500 Internal Server Error", http.StatusInternalServerError)
			return
		}
		// TODO: if fileInfo indicates the file is under 10MB, do the file
		// hashing here too. Also do the same for serveFile().
		// {{ join `admin` sitePrefix $.Path $entry.Name }}
		// {{ cdnBaseURL }}{{ join `admin` sitePrefix $.Path $entry.Name }}
		// cdn.nbrew.io/@bokwoon/path/to/file
		http.ServeContent(w, r, name, fileInfo.ModTime(), bytes.NewReader(buf.Bytes()))
		return
	}

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

	if path.Ext(urlPath) == ".html" {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		contentType := fileType.ContentType
		if strings.HasPrefix(contentType, "text") {
			contentType += "; charset=utf-8"
		}
		w.Header().Set("Content-Type", contentType)
	}
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("ETag", `"`+string(*dst)+`"`)
	http.ServeContent(w, r, name, fileInfo.ModTime(), bytes.NewReader(buf.Bytes()))
}

func (nbrew *Notebrew) admin(w http.ResponseWriter, r *http.Request, ip string) {
	urlPath := strings.Trim(strings.TrimPrefix(r.URL.Path, "/admin"), "/")
	head, tail, _ := strings.Cut(urlPath, "/")
	if head == "static" {
		serveFile(w, r, rootFS, urlPath)
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
		fileInfo, err := fs.Stat(nbrew.FS, path.Join(".", sitePrefix, urlPath))
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
