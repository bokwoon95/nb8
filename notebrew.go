package nb8

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"embed"
	"encoding/base32"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"html/template"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/bokwoon95/sq"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	"github.com/yuin/goldmark/parser"
	"github.com/yuin/goldmark/text"
	"golang.org/x/crypto/blake2b"
)

//go:embed embed static
var embedFS embed.FS

var rootFS fs.FS = embedFS

// trusted-proxies.txt: "", "", ""

// Notebrew represents a notebrew instance.
type Notebrew struct {
	// ConfigFS is the where the configuration files are stored.
	ConfigFS fs.FS

	// FS is the file system associated with the notebrew instance.
	FS FS
	// NOTE: now that we no longer have a New() function, it is up to the
	// callers to prep the initial folders: notes, output, output/images,
	// output/themes, pages, posts.

	// DB is the DB associated with the notebrew instance.
	DB *sql.DB

	// Dialect is Dialect of the database. Only sqlite, postgres and mysql
	// databases are supported.
	Dialect string

	// ErrorCode translates a database error into an dialect-specific error
	// code. If the error is not a database error or if no underlying
	// implementation is provided, ErrorCode should return an empty string.
	ErrorCode func(error) string

	Domain string // localhost:6444, example.com

	ContentDomain string // localhost:6444, example.com

	Port string // 6444, 443

	GzipGeneratedContent atomic.Bool

	Proxies map[netip.Addr]struct{}

	ProxyForwardedIPHeader map[netip.Addr]string

	Logger *slog.Logger
}

func (nbrew *Notebrew) xdomain() {
	// notebrew config domain
	// notebrew config contentdomain
	// notebrew config port
	// if port is 1234 and domain is localhost:1234,
}

func (nbrew *Notebrew) xcontentdomain() {
}

type contextKey struct{}

var loggerKey = &contextKey{}

func getLogger(ctx context.Context) *slog.Logger {
	if logger, ok := ctx.Value(loggerKey).(*slog.Logger); ok {
		return logger
	}
	return slog.Default()
}

func (nbrew *Notebrew) setSession(w http.ResponseWriter, r *http.Request, name string, value any) error {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)
	encoder := json.NewEncoder(buf)
	encoder.SetEscapeHTML(false)
	err := encoder.Encode(&value)
	if err != nil {
		return fmt.Errorf("marshaling JSON: %w", err)
	}
	cookie := &http.Cookie{
		Path:     "/",
		Name:     name,
		Secure:   nbrew.Domain != "localhost" && !strings.HasPrefix(nbrew.Domain, "localhost:"),
		HttpOnly: true,
		SameSite: http.SameSiteLaxMode,
	}
	if nbrew.DB == nil {
		cookie.Value = base64.URLEncoding.EncodeToString(buf.Bytes())
	} else {
		var sessionToken [8 + 16]byte
		binary.BigEndian.PutUint64(sessionToken[:8], uint64(time.Now().Unix()))
		_, err := rand.Read(sessionToken[8:])
		if err != nil {
			return fmt.Errorf("reading rand: %w", err)
		}
		var sessionTokenHash [8 + blake2b.Size256]byte
		checksum := blake2b.Sum256(sessionToken[8:])
		copy(sessionTokenHash[:8], sessionToken[:8])
		copy(sessionTokenHash[8:], checksum[:])
		_, err = sq.ExecContext(r.Context(), nbrew.DB, sq.CustomQuery{
			Dialect: nbrew.Dialect,
			Format:  "INSERT INTO session (session_token_hash, data) VALUES ({sessionTokenHash}, {data})",
			Values: []any{
				sq.BytesParam("sessionTokenHash", sessionTokenHash[:]),
				sq.StringParam("data", strings.TrimSpace(buf.String())),
			},
		})
		if err != nil {
			return fmt.Errorf("saving session: %w", err)
		}
		cookie.Value = strings.TrimLeft(hex.EncodeToString(sessionToken[:]), "0")
	}
	http.SetCookie(w, cookie)
	return nil
}

func (nbrew *Notebrew) getSession(r *http.Request, name string, valuePtr any) (ok bool, err error) {
	cookie, _ := r.Cookie(name)
	if cookie == nil {
		return false, nil
	}
	var dataBytes []byte
	if nbrew.DB == nil {
		dataBytes, err = base64.URLEncoding.DecodeString(cookie.Value)
		if err != nil {
			return false, nil
		}
	} else {
		sessionToken, err := hex.DecodeString(fmt.Sprintf("%048s", cookie.Value))
		if err != nil {
			return false, nil
		}
		var sessionTokenHash [8 + blake2b.Size256]byte
		checksum := blake2b.Sum256(sessionToken[8:])
		copy(sessionTokenHash[:8], sessionToken[:8])
		copy(sessionTokenHash[8:], checksum[:])
		creationTime := time.Unix(int64(binary.BigEndian.Uint64(sessionTokenHash[:8])), 0)
		if time.Now().Sub(creationTime) > 5*time.Minute {
			return false, nil
		}
		dataBytes, err = sq.FetchOneContext(r.Context(), nbrew.DB, sq.CustomQuery{
			Dialect: nbrew.Dialect,
			Format:  "SELECT {*} FROM session WHERE session_token_hash = {sessionTokenHash}",
			Values: []any{
				sq.BytesParam("sessionTokenHash", sessionTokenHash[:]),
			},
		}, func(row *sq.Row) []byte {
			return row.Bytes("data")
		})
		if err != nil {
			if errors.Is(err, sql.ErrNoRows) {
				return false, nil
			}
			return false, err
		}
	}
	err = json.Unmarshal(dataBytes, valuePtr)
	if err != nil {
		return false, err
	}
	return true, nil
}

func (nbrew *Notebrew) clearSession(w http.ResponseWriter, r *http.Request, name string) {
	cookie, _ := r.Cookie(name)
	if cookie == nil {
		return
	}
	http.SetCookie(w, &http.Cookie{
		Path:     "/",
		Name:     name,
		Value:    "0",
		MaxAge:   -1,
		Secure:   nbrew.Domain != "localhost" && !strings.HasPrefix(nbrew.Domain, "localhost:"),
		HttpOnly: true,
	})
	if nbrew.DB == nil {
		return
	}
	sessionToken, err := hex.DecodeString(fmt.Sprintf("%048s", cookie.Value))
	if err != nil {
		return
	}
	var sessionTokenHash [8 + blake2b.Size256]byte
	checksum := blake2b.Sum256(sessionToken[8:])
	copy(sessionTokenHash[:8], sessionToken[:8])
	copy(sessionTokenHash[8:], checksum[:])
	_, err = sq.ExecContext(r.Context(), nbrew.DB, sq.CustomQuery{
		Dialect: nbrew.Dialect,
		Format:  "DELETE FROM session WHERE session_token_hash = {sessionTokenHash}",
		Values: []any{
			sq.BytesParam("sessionTokenHash", sessionTokenHash[:]),
		},
	})
	if err != nil {
		logger, ok := r.Context().Value(loggerKey).(*slog.Logger)
		if !ok {
			logger = slog.Default()
		}
		logger.Error(err.Error())
	}
}

func (nbrew *Notebrew) Close() error {
	if nbrew.DB == nil {
		return nil
	}
	if nbrew.Dialect == "sqlite" {
		nbrew.DB.Exec("PRAGMA analysis_limit(400); PRAGMA optimize;")
	}
	return nbrew.DB.Close()
}

func getAuthenticationTokenHash(r *http.Request) []byte {
	var str string
	header := r.Header.Get("Authorization")
	if strings.HasPrefix(header, "Notebrew ") {
		str = strings.TrimPrefix(header, "Notebrew ")
	} else {
		cookie, _ := r.Cookie("authentication")
		if cookie != nil {
			str = cookie.Value
		}
	}
	if str == "" {
		return nil
	}
	authenticationToken, err := hex.DecodeString(fmt.Sprintf("%048s", str))
	if err != nil {
		return nil
	}
	var authenticationTokenHash [8 + blake2b.Size256]byte
	checksum := blake2b.Sum256(authenticationToken[8:])
	copy(authenticationTokenHash[:8], authenticationToken[:8])
	copy(authenticationTokenHash[8:], checksum[:])
	return authenticationTokenHash[:]
}

var base32Encoding = base32.NewEncoding("0123456789abcdefghjkmnpqrstvwxyz").WithPadding(base32.NoPadding)

var goldmarkMarkdown = func() goldmark.Markdown {
	md := goldmark.New()
	md.Parser().AddOptions(parser.WithAttribute())
	extension.Table.Extend(md)
	return md
}()

func stripMarkdownStyles(src []byte) string {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)
	var node ast.Node
	nodes := []ast.Node{
		goldmarkMarkdown.Parser().Parse(text.NewReader(src)),
	}
	for len(nodes) > 0 {
		node, nodes = nodes[len(nodes)-1], nodes[:len(nodes)-1]
		if node == nil {
			continue
		}
		switch node := node.(type) {
		case *ast.Text:
			buf.Write(node.Text(src))
		}
		nodes = append(nodes, node.NextSibling(), node.FirstChild())
	}
	// Manually escape backslashes (goldmark may be able to do this,
	// investigate).
	var b strings.Builder
	output := buf.Bytes()
	// Jump to the location of each backslash found in the output.
	for i := bytes.IndexByte(output, '\\'); i >= 0; i = bytes.IndexByte(output, '\\') {
		b.Write(output[:i])
		char, width := utf8.DecodeRune(output[i+1:])
		if char != utf8.RuneError {
			b.WriteRune(char)
		}
		output = output[i+1+width:]
	}
	b.Write(output)
	return b.String()
}

var isForbiddenChar = []bool{
	' ': true, '!': true, '"': true, '#': true, '$': true, '%': true, '&': true, '\'': true,
	'(': true, ')': true, '*': true, '+': true, ',': true, '/': true, ':': true, ';': true,
	'<': true, '>': true, '=': true, '?': true, '[': true, ']': true, '\\': true, '^': true,
	'`': true, '{': true, '}': true, '|': true, '~': true,
}

func urlSafe(s string) string {
	s = strings.TrimSpace(s)
	var b strings.Builder
	b.Grow(len(s))
	for _, char := range s {
		if utf8.RuneCountInString(b.String()) >= 80 {
			break
		}
		if char == ' ' {
			b.WriteRune('-')
			continue
		}
		if char == '-' || (char >= '0' && char <= '9') || (char >= 'a' && char <= 'z') {
			b.WriteRune(char)
			continue
		}
		if char >= 'A' && char <= 'Z' {
			b.WriteRune(unicode.ToLower(char))
			continue
		}
		n := int(char)
		if n < len(isForbiddenChar) && isForbiddenChar[n] {
			continue
		}
		b.WriteRune(char)
	}
	return strings.Trim(b.String(), ".")
}

var (
	commonPasswordHashes = make(map[string]struct{})
	stylesCSS            string
	stylesCSSHash        string
	baselineJS           string
	baselineJSHash       string
	folderJS             string
	folderJSHash         string
)

func init() {
	// top-10000-passwords.txt
	file, err := rootFS.Open("embed/top-10000-passwords.txt")
	if err != nil {
		return
	}
	defer file.Close()
	reader := bufio.NewReader(file)
	done := false
	for {
		if done {
			break
		}
		line, err := reader.ReadBytes('\n')
		done = err == io.EOF
		if err != nil && !done {
			panic(err)
		}
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		hash := blake2b.Sum256([]byte(line))
		encodedHash := hex.EncodeToString(hash[:])
		commonPasswordHashes[encodedHash] = struct{}{}
	}
	// styles.css
	b, err := fs.ReadFile(rootFS, "static/styles.css")
	if err != nil {
		return
	}
	hash := sha256.Sum256(b)
	stylesCSS = string(b)
	stylesCSSHash = "'sha256-" + base64.StdEncoding.EncodeToString(hash[:]) + "'"
	// baseline.js
	b, err = fs.ReadFile(rootFS, "static/baseline.js")
	if err != nil {
		return
	}
	hash = sha256.Sum256(b)
	baselineJS = string(b)
	baselineJSHash = "'sha256-" + base64.StdEncoding.EncodeToString(hash[:]) + "'"
	// folder.js
	b, err = fs.ReadFile(rootFS, "static/folder.js")
	if err != nil {
		return
	}
	hash = sha256.Sum256(b)
	folderJS = string(b)
	folderJSHash = "'sha256-" + base64.StdEncoding.EncodeToString(hash[:]) + "'"
}

func IsCommonPassword(password []byte) bool {
	hash := blake2b.Sum256(password)
	encodedHash := hex.EncodeToString(hash[:])
	_, ok := commonPasswordHashes[encodedHash]
	return ok
}

func (nbrew *Notebrew) realClientIP(r *http.Request) string {
	// Reference: https://adam-p.ca/blog/2022/03/x-forwarded-for/
	// proxies.json example:
	// {proxyIPs: ["<ip>", "<ip>", "<ip>"], forwardedIPHeaders: {"<ip>": "X-Real-IP", "<ip>": "CF-Connecting-IP"}}
	ip, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return ""
	}
	remoteAddr, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return ""
	}
	// If we don't have any proxy servers configured (i.e. we are directly
	// connected to the internet), treat remoteAddr as the real client IP.
	if len(nbrew.ProxyForwardedIPHeader) == 0 && len(nbrew.Proxies) == 0 {
		return remoteAddr.String()
	}
	// If remoteAddr is trusted to populate a known header with the real client
	// IP, look in that header.
	if trustedHeader, ok := nbrew.ProxyForwardedIPHeader[remoteAddr]; ok {
		ipAddr, err := netip.ParseAddr(strings.TrimSpace(r.Header.Get(trustedHeader)))
		if err != nil {
			return ""
		}
		return ipAddr.String()
	}
	// Check X-Forwarded-For header only if remoteAddr is the IP of a proxy
	// server.
	_, ok := nbrew.Proxies[remoteAddr]
	if !ok {
		return remoteAddr.String()
	}
	// Loop over all IP addresses in X-Forwarded-For headers from right to
	// left. We want to rightmost IP address that isn't a proxy server's IP
	// address.
	values := r.Header.Values("X-Forwarded-For")
	for i := len(values) - 1; i >= 0; i-- {
		ips := strings.Split(values[i], ",")
		for j := len(ips) - 1; j >= 0; j-- {
			ip := ips[j]
			ipAddr, err := netip.ParseAddr(strings.TrimSpace(ip))
			if err != nil {
				continue
			}
			_, ok := nbrew.Proxies[ipAddr]
			if ok {
				continue
			}
			return ipAddr.String()
		}
	}
	return ""
}

func fileSizeToString(size int64) string {
	// https://yourbasic.org/golang/formatting-byte-size-to-human-readable-format/
	if size < 0 {
		return ""
	}
	const unit = 1000
	if size < unit {
		return fmt.Sprintf("%d B", size)
	}
	div, exp := int64(unit), 0
	for n := size / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(size)/float64(div), "kMGTPE"[exp])
}

// {{ if contains sitePrefix "." }}https://{{ sitePrefix }}/{{ else }}{{ scheme }}{{ if sitePrefix }}{{ sitePrefix }}.{{ end }}{{ $.ContentDomain }}/{{ end }}
// {{ if contains sitePrefix "." }}{{ sitePrefix }}{{ else }}{{ if sitePrefix }}{{ sitePrefix }}.{{ end }}{{ $.ContentDomain }}{{ end }}

var gzipWriterPool = sync.Pool{
	New: func() any {
		// Use compression level 4 for best balance between space and
		// performance.
		// https://blog.klauspost.com/gzip-performance-for-go-webservers/
		gzipWriter, _ := gzip.NewWriterLevel(nil, 4)
		return gzipWriter
	},
}

var hashPool = sync.Pool{
	New: func() any {
		hash, err := blake2b.New256(nil)
		if err != nil {
			panic(err)
		}
		return hash
	},
}

var bytesPool = sync.Pool{
	New: func() any {
		b := make([]byte, 0, 64)
		return &b
	},
}

func executeTemplate(w http.ResponseWriter, r *http.Request, modtime time.Time, tmpl *template.Template, data any) {
	buf := bufPool.Get().(*bytes.Buffer)
	buf.Reset()
	defer bufPool.Put(buf)

	hasher := hashPool.Get().(hash.Hash)
	hasher.Reset()
	defer hashPool.Put(hasher)

	multiWriter := io.MultiWriter(buf, hasher)
	gzipWriter := gzipWriterPool.Get().(*gzip.Writer)
	gzipWriter.Reset(multiWriter)
	defer gzipWriterPool.Put(gzipWriter)

	err := tmpl.Execute(gzipWriter, data)
	if err != nil {
		getLogger(r.Context()).Error(err.Error(), slog.String("data", fmt.Sprintf("%#v", data)))
		internalServerError(w, r, err)
		return
	}
	err = gzipWriter.Close()
	if err != nil {
		getLogger(r.Context()).Error(err.Error())
		internalServerError(w, r, err)
		return
	}

	b := bytesPool.Get().(*[]byte)
	*b = (*b)[:0]
	defer bytesPool.Put(b)

	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Content-Encoding", "gzip")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("ETag", `"`+hex.EncodeToString(hasher.Sum(*b))+`"`)
	http.ServeContent(w, r, "", modtime, bytes.NewReader(buf.Bytes()))
}

// TODO: we can retire this function since the cdn url will always be hardcoded
// to cdn.nbrew.io, instead make it a global variable built at init time.
// Besides, this is only applicable to user sites and not the admin site.
func contentSecurityPolicy(w http.ResponseWriter, cdnBaseURL string, allowCaptcha bool) {
	var b strings.Builder
	// default-src
	b.WriteString("default-src 'none';")
	// script-src
	b.WriteString(" script-src 'self' 'unsafe-hashes' " + baselineJSHash + " " + folderJSHash)
	if cdnBaseURL != "" {
		b.WriteString(" " + cdnBaseURL)
	}
	if allowCaptcha {
		b.WriteString(" https://hcaptcha.com https://*.hcaptcha.com")
	}
	b.WriteString(";")
	// connect-src
	b.WriteString(" connect-src 'self'")
	if allowCaptcha {
		b.WriteString(" https://hcaptcha.com https://*.hcaptcha.com")
	}
	b.WriteString(";")
	// img-src
	b.WriteString(" img-src 'self' data:")
	b.WriteString(" https://www.jpl.nasa.gov")
	if cdnBaseURL != "" {
		b.WriteString(" " + cdnBaseURL)
	}
	b.WriteString(";")
	// style-src
	b.WriteString(" style-src 'self' 'unsafe-inline'")
	if cdnBaseURL != "" {
		b.WriteString(" " + cdnBaseURL)
	}
	if allowCaptcha {
		b.WriteString(" https://hcaptcha.com https://*.hcaptcha.com")
	}
	b.WriteString(";")
	// base-uri
	b.WriteString(" base-uri 'self';")
	// form-action
	b.WriteString(" form-action 'self';")
	// manifest-src
	b.WriteString(" manifest-src 'self';")
	// frame-src
	if allowCaptcha {
		b.WriteString(" frame-src https://hcaptcha.com https://*.hcaptcha.com;")
	}
	w.Header().Set("Content-Security-Policy", b.String())
}

type FileType struct {
	Ext         string
	ContentType string
	IsGzippable bool
}

var fileTypes = map[string]FileType{
	".html":  {Ext: ".html", ContentType: "text/html; charset=utf-8", IsGzippable: true},
	".css":   {Ext: ".css", ContentType: "text/css; charset=utf-8", IsGzippable: true},
	".js":    {Ext: ".js", ContentType: "text/javascript; charset=utf-8", IsGzippable: true},
	".md":    {Ext: ".md", ContentType: "text/markdown; charset=utf-8", IsGzippable: true},
	".txt":   {Ext: ".txt", ContentType: "text/plain; charset=utf-8", IsGzippable: true},
	".svg":   {Ext: ".svg", ContentType: "image/svg+xml", IsGzippable: true},
	".ico":   {Ext: ".ico", ContentType: "image/ico", IsGzippable: true},
	".jpeg":  {Ext: ".jpeg", ContentType: "image/jpeg", IsGzippable: false},
	".jpg":   {Ext: ".jpg", ContentType: "image/jpeg", IsGzippable: false},
	".png":   {Ext: ".png", ContentType: "image/png", IsGzippable: false},
	".webp":  {Ext: ".webp", ContentType: "image/webp", IsGzippable: false},
	".gif":   {Ext: ".gif", ContentType: "image/gif", IsGzippable: false},
	".eot":   {Ext: ".eot", ContentType: "font/eot", IsGzippable: true},
	".otf":   {Ext: ".otf", ContentType: "font/otf", IsGzippable: true},
	".ttf":   {Ext: ".ttf", ContentType: "font/ttf", IsGzippable: true},
	".woff":  {Ext: ".woff", ContentType: "font/woff", IsGzippable: false},
	".woff2": {Ext: ".woff2", ContentType: "font/woff2", IsGzippable: false},
	".json":  {Ext: ".json", ContentType: "application/json", IsGzippable: true},
	".xml":   {Ext: ".xml", ContentType: "application/xml", IsGzippable: true},
}

func (nbrew *Notebrew) contentURL(sitePrefix string) string {
	if strings.Contains(sitePrefix, ".") {
		return "https://" + sitePrefix
	}
	// NOTE: if we're proxying localhost to the outside world, our domain *is
	// not* localhost. It is whichever domain we are hosting the CMS on.
	if nbrew.Domain == "localhost" || strings.HasPrefix(nbrew.Domain, "localhost:") {
		if sitePrefix != "" {
			return "http://" + strings.TrimPrefix(sitePrefix, "@") + "." + nbrew.Domain
		}
		return "http://" + nbrew.Domain
	}
	if sitePrefix != "" {
		return "https://" + strings.TrimPrefix(sitePrefix, "@") + "." + nbrew.ContentDomain
	}
	return "https://" + nbrew.ContentDomain
}
