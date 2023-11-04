package main

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/bokwoon95/nb8"
	"github.com/caddyserver/certmagic"
	"github.com/go-sql-driver/mysql"
	"github.com/jackc/pgconn"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/libdns/cloudflare"
	"github.com/libdns/godaddy"
	"github.com/libdns/namecheap"
	"github.com/libdns/porkbun"
	"github.com/mholt/acmez"
)

type SMTPConfig struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Host     string `json:"host,omitempty"`
	Port     string `json:"port,omitempty"`
}

type CaptchaConfig struct {
	SecretKey string `json:"secretKey,omitempty"`
	SiteKey   string `json:"siteKey,omitempty"`
}

var (
	open     = func(address string) {}
	startmsg = "Running on %s\n"
)

func main() {
	// Wrap everything in an anonymous function so that deferred functions are
	// run before we call os.Exit(1).
	err := func() error {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		nbrew := &nb8.Notebrew{
			Logger: slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{
				AddSource: true,
			})),
		}

		var configFolder string
		flagset := flag.NewFlagSet("", flag.ContinueOnError)
		flagset.StringVar(&configFolder, "config-folder", "", "")
		err = flagset.Parse(os.Args[1:])
		if err != nil {
			return err
		}
		if configFolder == "" {
			XDGConfigHome := os.Getenv("XDG_CONFIG_HOME")
			if XDGConfigHome != "" {
				configFolder = filepath.Join(XDGConfigHome, "notebrew-config")
			} else {
				configFolder = filepath.Join(homeDir, "notebrew-config")
			}
			err := os.MkdirAll(configFolder, 0755)
			if err != nil {
				return err
			}
		} else {
			configFolder = filepath.Clean(configFolder)
			_, err := os.Stat(configFolder)
			if err != nil {
				return err
			}
		}
		nbrew.ConfigFS = os.DirFS(configFolder)

		b, err := os.ReadFile(filepath.Join(configFolder, "domain.txt"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configFolder, "domain.txt"), err)
		}
		if len(b) > 0 {
			nbrew.Domain = string(b)
		} else {
			nbrew.Domain = "localhost:6444"
		}
		if strings.Contains(nbrew.Domain, "127.0.0.1") {
			return fmt.Errorf("%s: don't use 127.0.0.1, use localhost instead", filepath.Join(configFolder, "domain.txt"))
		}

		b, err = os.ReadFile(filepath.Join(configFolder, "content-domain.txt"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configFolder, "content-domain.txt"), err)
		}
		if len(b) > 0 {
			nbrew.ContentDomain = string(b)
		} else {
			nbrew.ContentDomain = nbrew.Domain
		}
		if strings.Contains(nbrew.ContentDomain, "127.0.0.1") {
			return fmt.Errorf("%s: don't use 127.0.0.1, use localhost instead", filepath.Join(configFolder, "content-domain.txt"))
		}

		domainIsLocalhost := nbrew.Domain == "localhost" || strings.HasPrefix(nbrew.Domain, "localhost:")
		contentDomainIsLocalhost := nbrew.ContentDomain == "localhost" || strings.HasPrefix(nbrew.ContentDomain, "localhost:")
		if domainIsLocalhost && contentDomainIsLocalhost {
			nbrew.Scheme = "http://"
			if nbrew.Domain != nbrew.ContentDomain {
				return fmt.Errorf("%s: %s: if localhost, domains must be the same", filepath.Join(configFolder, "domain.txt"), filepath.Join(configFolder, "content-domain.txt"))
			}
		} else if !domainIsLocalhost && !contentDomainIsLocalhost {
			nbrew.Scheme = "https://"
		} else {
			return fmt.Errorf("%s: %s: localhost and non-localhost domains cannot be mixed", filepath.Join(configFolder, "domain.txt"), filepath.Join(configFolder, "content-domain.txt"))
		}

		b, err = os.ReadFile(filepath.Join(configFolder, "multisite.txt"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configFolder, "multisite.txt"), err)
		}
		if len(b) > 0 {
			str := string(b)
			if str != "" && str != "subdomain" && str != "subdirectory" {
				return fmt.Errorf("%s: invalid value %q (possible values: subdomain, subdirectory)", filepath.Join(configFolder, "multisite.txt"), str)
			}
			nbrew.Multisite = str
		}
		if nbrew.Multisite == "" && domainIsLocalhost && contentDomainIsLocalhost {
			nbrew.Multisite = "subdirectory"
		}

		b, err = os.ReadFile(filepath.Join(configFolder, "database.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configFolder, "database.json"), err)
		}
		if len(b) > 0 {
			var databaseConfig struct {
				Dialect  string            `json:"dialect,omitempty"`
				Filepath string            `json:"filepath,omitempty"`
				User     string            `json:"user,omitempty"`
				Password string            `json:"password,omitempty"`
				Host     string            `json:"host,omitempty"`
				Port     string            `json:"port,omitempty"`
				DBName   string            `json:"dbname,omitempty"`
				Params   map[string]string `json:"params,omitempty"`
			}
			decoder := json.NewDecoder(bytes.NewReader(b))
			decoder.DisallowUnknownFields()
			err := decoder.Decode(&databaseConfig)
			if err != nil {
				return fmt.Errorf("%s: %w", filepath.Join(configFolder, "database.json"), err)
			}
			switch databaseConfig.Dialect {
			case "sqlite":
				if databaseConfig.Filepath == "" {
					return fmt.Errorf("%s: sqlite: missing filepath field", filepath.Join(configFolder, "database.json"))
				}
				databaseConfig.Filepath, err = filepath.Abs(databaseConfig.Filepath)
				if err != nil {
					return fmt.Errorf("%s: sqlite: %w", filepath.Join(configFolder, "database.json"), err)
				}
				dataSourceName := databaseConfig.Filepath + "?" + sqliteQueryString(databaseConfig.Params)
				nbrew.Dialect = "sqlite"
				nbrew.DB, err = sql.Open(sqliteDriverName, dataSourceName)
				if err != nil {
					return fmt.Errorf("%s: sqlite: open %s: %w", filepath.Join(configFolder, "database.json"), dataSourceName, err)
				}
				err = nbrew.DB.Ping()
				if err != nil {
					return fmt.Errorf("%s: sqlite: ping %s: %w", filepath.Join(configFolder, "database.json"), dataSourceName, err)
				}
			case "postgres":
				values := make(url.Values)
				for key, value := range databaseConfig.Params {
					switch key {
					case "sslmode":
						values.Set(key, value)
					}
				}
				if _, ok := databaseConfig.Params["sslmode"]; !ok {
					values.Set("sslmode", "disable")
				}
				if databaseConfig.Port == "" {
					databaseConfig.Port = "5432"
				}
				uri := url.URL{
					Scheme:   "postgres",
					User:     url.UserPassword(databaseConfig.User, databaseConfig.Password),
					Host:     databaseConfig.Host + ":" + databaseConfig.Port,
					Path:     databaseConfig.DBName,
					RawQuery: values.Encode(),
				}
				dataSourceName := uri.String()
				nbrew.Dialect = "postgres"
				nbrew.DB, err = sql.Open("pgx", dataSourceName)
				if err != nil {
					return fmt.Errorf("%s: postgres: open %s: %w", filepath.Join(configFolder, "database.json"), dataSourceName, err)
				}
				err = nbrew.DB.Ping()
				if err != nil {
					return fmt.Errorf("%s: postgres: ping %s: %w", filepath.Join(configFolder, "database.json"), dataSourceName, err)
				}
				nbrew.ErrorCode = func(err error) string {
					var pgErr *pgconn.PgError
					if errors.As(err, &pgErr) {
						return pgErr.Code
					}
					return ""
				}
			case "mysql":
				values := make(url.Values)
				for key, value := range databaseConfig.Params {
					switch key {
					case "charset", "collation", "loc", "maxAllowedPacket",
						"readTimeout", "rejectReadOnly", "serverPubKey", "timeout",
						"tls", "writeTimeout", "connectionAttributes":
						values.Set(key, value)
					}
				}
				values.Set("multiStatements", "true")
				values.Set("parseTime", "true")
				if databaseConfig.Port == "" {
					databaseConfig.Port = "3306"
				}
				// We are parsing the DSN and setting the username and password
				// fields separately because it's the only way to have special
				// characters inside the username and password for the go mysql
				// driver.
				//
				// https://github.com/go-sql-driver/mysql/issues/1323
				config, err := mysql.ParseDSN(fmt.Sprintf("tcp(%s:%s)/%s?%s", databaseConfig.Host, databaseConfig.Port, url.PathEscape(databaseConfig.DBName), values.Encode()))
				if err != nil {
					return err
				}
				config.User = databaseConfig.User
				config.Passwd = databaseConfig.Password
				driver, err := mysql.NewConnector(config)
				if err != nil {
					return err
				}
				nbrew.Dialect = "mysql"
				nbrew.DB = sql.OpenDB(driver)
				if err != nil {
					return fmt.Errorf("%s: mysql: open %s: %w", filepath.Join(configFolder, "database.json"), config.FormatDSN(), err)
				}
				err = nbrew.DB.Ping()
				if err != nil {
					return fmt.Errorf("%s: mysql: ping %s: %w", filepath.Join(configFolder, "database.json"), config.FormatDSN(), err)
				}
				nbrew.ErrorCode = func(err error) string {
					var mysqlErr *mysql.MySQLError
					if errors.As(err, &mysqlErr) {
						return strconv.FormatUint(uint64(mysqlErr.Number), 10)
					}
					return ""
				}
			case "":
				return fmt.Errorf("%s: missing dialect field", filepath.Join(configFolder, "database.json"))
			default:
				return fmt.Errorf("%s: unsupported dialect %q (possible values: sqlite, postgres, mysql)", filepath.Join(configFolder, "database.json"), databaseConfig.Dialect)
			}
			err = nb8.Automigrate(nbrew.Dialect, nbrew.DB)
			if err != nil {
				return err
			}
		}

		b, err = os.ReadFile(filepath.Join(configFolder, "admin-folder.txt"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configFolder, "admin-folder.txt"), err)
		}
		adminFolder := string(b)
		if adminFolder == "" {
			XDGDataHome := os.Getenv("XDG_DATA_HOME")
			if XDGDataHome != "" {
				adminFolder = filepath.Join(XDGDataHome, "notebrew-admin")
			} else {
				adminFolder = filepath.Join(homeDir, "notebrew-admin")
			}
			err := os.MkdirAll(adminFolder, 0755)
			if err != nil {
				return err
			}
			nbrew.FS = nb8.NewLocalFS(adminFolder, os.TempDir())
		} else if adminFolder == "database" {
			if nbrew.DB == nil {
				return fmt.Errorf("%s: cannot use database as filesystem because %s is missing", filepath.Join(configFolder, "admin-folder.txt"), filepath.Join(configFolder, "database.json"))
			}
			b, err = os.ReadFile(filepath.Join(configFolder, "s3.json"))
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("%s: %w", filepath.Join(configFolder, "s3.json"), err)
			}
			if len(b) > 0 {
				var s3Config struct {
					Endpoint        string `json:"endpoint,omitempty"`
					Region          string `json:"region,omitempty"`
					Bucket          string `json:"bucket,omitempty"`
					AccessKeyID     string `json:"accessKeyID,omitempty"`
					SecretAccessKey string `json:"secretAccessKey,omitempty"`
				}
				decoder := json.NewDecoder(bytes.NewReader(b))
				decoder.DisallowUnknownFields()
				err := decoder.Decode(&s3Config)
				if err != nil {
					return fmt.Errorf("%s: %w", filepath.Join(configFolder, "s3.json"), err)
				}
				if s3Config.Endpoint == "" {
					return fmt.Errorf("%s: missing endpoint field", filepath.Join(configFolder, "s3.json"))
				}
				if s3Config.Region == "" {
					return fmt.Errorf("%s: missing region field", filepath.Join(configFolder, "s3.json"))
				}
				if s3Config.Bucket == "" {
					return fmt.Errorf("%s: missing bucket field", filepath.Join(configFolder, "s3.json"))
				}
				if s3Config.AccessKeyID == "" {
					return fmt.Errorf("%s: missing accessKeyID field", filepath.Join(configFolder, "s3.json"))
				}
				if s3Config.SecretAccessKey == "" {
					return fmt.Errorf("%s: missing secretAccessKey field", filepath.Join(configFolder, "s3.json"))
				}
				nbrew.FS = nb8.NewRemoteFS(nbrew.Dialect, nbrew.DB, nbrew.ErrorCode, &nb8.S3Storage{
					Client: s3.New(s3.Options{
						BaseEndpoint: aws.String(s3Config.Endpoint),
						Region:       s3Config.Region,
						Credentials:  aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(s3Config.AccessKeyID, s3Config.SecretAccessKey, "")),
					}),
					Bucket: s3Config.Bucket,
				})
			} else {
				b, err = os.ReadFile(filepath.Join(configFolder, "objects-folder.txt"))
				if err != nil && !errors.Is(err, fs.ErrNotExist) {
					return fmt.Errorf("%s: %w", filepath.Join(configFolder, "objects-folder.txt"), err)
				}
				objectsFolder := string(b)
				if objectsFolder == "" {
					XDGDataHome := os.Getenv("XDG_DATA_HOME")
					if XDGDataHome != "" {
						objectsFolder = filepath.Join(XDGDataHome, "notebrew-objects")
					} else {
						objectsFolder = filepath.Join(homeDir, "notebrew-objects")
					}
					err := os.MkdirAll(objectsFolder, 0755)
					if err != nil {
						return err
					}
				} else {
					objectsFolder = path.Clean(objectsFolder)
					_, err := os.Stat(objectsFolder)
					if err != nil {
						return err
					}
				}
				nbrew.FS = nb8.NewRemoteFS(nbrew.Dialect, nbrew.DB, nbrew.ErrorCode, nb8.NewFileStorage(objectsFolder, os.TempDir()))
			}
		} else {
			adminFolder = filepath.Clean(adminFolder)
			_, err := os.Stat(adminFolder)
			if err != nil {
				return err
			}
			nbrew.FS = nb8.NewLocalFS(adminFolder, os.TempDir())
		}
		dirs := []string{
			"notes",
			"output",
			"output/images",
			"output/themes",
			"pages",
			"posts",
		}
		for _, dir := range dirs {
			err = nbrew.FS.Mkdir(dir, 0755)
			if err != nil && !errors.Is(err, fs.ErrExist) {
				return err
			}
		}

		defer nbrew.Close()
		args := flagset.Args()
		if len(args) > 0 {
			command, args := args[0], args[1:]
			_ = args
			switch command {
			default:
				return fmt.Errorf("unknown command %s", command)
			}
		}

		var dns01Solver acmez.Solver
		b, err = os.ReadFile(filepath.Join(configFolder, "dns.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configFolder, "dns.json"), err)
		}
		if len(b) > 0 {
			var dnsConfig struct {
				Provider  string `json:"provider,omitempty"`
				Username  string `json:"username,omitempty"`
				APIKey    string `json:"apiKey,omitempty"`
				APIToken  string `json:"apiToken,omitempty"`
				SecretKey string `json:"secretKey,omitempty"`
			}
			decoder := json.NewDecoder(bytes.NewReader(b))
			decoder.DisallowUnknownFields()
			err := decoder.Decode(&dnsConfig)
			if err != nil {
				return fmt.Errorf("%s: %w", filepath.Join(configFolder, "dns.json"), err)
			}
			switch dnsConfig.Provider {
			case "namecheap":
				if dnsConfig.Username == "" {
					return fmt.Errorf("%s: namecheap: missing username field", filepath.Join(configFolder, "dns.json"))
				}
				if dnsConfig.APIKey == "" {
					return fmt.Errorf("%s: namecheap: missing apiKey field", filepath.Join(configFolder, "dns.json"))
				}
				resp, err := http.Get("https://ipv4.icanhazip.com")
				if err != nil {
					return fmt.Errorf("determining the IP address of this machine by calling https://ipv4.icanhazip.com: %w", err)
				}
				defer resp.Body.Close()
				var b strings.Builder
				_, err = io.Copy(&b, resp.Body)
				if err != nil {
					return fmt.Errorf("https://ipv4.icanhazip.com: reading response body: %w", err)
				}
				err = resp.Body.Close()
				if err != nil {
					return err
				}
				clientIP := strings.TrimSpace(b.String())
				ip, err := netip.ParseAddr(clientIP)
				if err != nil {
					return fmt.Errorf("could not determine IP address of the current machine: https://ipv4.icanhazip.com returned %q which is not an IP address", clientIP)
				}
				if !ip.Is4() {
					return fmt.Errorf("the current machine's IP address (%s) is not IPv4: an IPv4 address is needed to integrate with namecheap's API", clientIP)
				}
				dns01Solver = &certmagic.DNS01Solver{
					DNSProvider: &namecheap.Provider{
						APIKey:      dnsConfig.APIKey,
						User:        dnsConfig.Username,
						APIEndpoint: "https://api.namecheap.com/xml.response",
						ClientIP:    clientIP,
					},
				}
			case "cloudflare":
				if dnsConfig.APIToken == "" {
					return fmt.Errorf("%s: cloudflare: missing apiToken field", filepath.Join(configFolder, "dns.json"))
				}
				dns01Solver = &certmagic.DNS01Solver{
					DNSProvider: &cloudflare.Provider{
						APIToken: dnsConfig.APIToken,
					},
				}
			case "porkbun":
				if dnsConfig.APIKey == "" {
					return fmt.Errorf("%s: porkbun: missing apiKey field", filepath.Join(configFolder, "dns.json"))
				}
				if dnsConfig.SecretKey == "" {
					return fmt.Errorf("%s: porkbun: missing secretKey field", filepath.Join(configFolder, "dns.json"))
				}
				dns01Solver = &certmagic.DNS01Solver{
					DNSProvider: &porkbun.Provider{
						APIKey:       dnsConfig.APIKey,
						APISecretKey: dnsConfig.SecretKey,
					},
				}
			case "godaddy":
				if dnsConfig.APIToken == "" {
					return fmt.Errorf("%s: godaddy: missing apiToken field", filepath.Join(configFolder, "dns.json"))
				}
				dns01Solver = &certmagic.DNS01Solver{
					DNSProvider: &godaddy.Provider{
						APIToken: dnsConfig.APIToken,
					},
				}
			case "":
				return fmt.Errorf("%s: missing provider field", filepath.Join(configFolder, "dns.json"))
			default:
				return fmt.Errorf("%s: unsupported provider %q (possible values: namecheap, cloudflare, porkbun, godaddy)", filepath.Join(configFolder, "dns.json"), dnsConfig.Provider)
			}
		}
		if nbrew.Scheme == "https://" && nbrew.Multisite == "subdomain" && dns01Solver == nil {
			return fmt.Errorf("%s: cannot use \"subdomain\" because %s has not been configured, please use \"subdirectory\" instead", filepath.Join(configFolder, "multisite.txt"), filepath.Join(configFolder, "dns.json"))
		}
		// Create a new server (this step will provision the certificates for
		// serving HTTPS traffic, and will return an error if certmagic fails
		// to obtain the necessary certificates).
		server, err := nbrew.NewServer(dns01Solver)
		if err != nil {
			return err
		}

		// Manually acquire a listener instead of using the convenient
		// ListenAndServe() so that we can report back to the user if the port
		// is already in use.
		listener, err := net.Listen("tcp", server.Addr)
		if err != nil {
			var errno syscall.Errno
			if !errors.As(err, &errno) {
				return err
			}
			// WSAEADDRINUSE copied from
			// https://cs.opensource.google/go/x/sys/+/refs/tags/v0.6.0:windows/zerrors_windows.go;l=2680
			// To avoid importing an entire 3rd party library just to use a constant.
			const WSAEADDRINUSE = syscall.Errno(10048)
			if errno == syscall.EADDRINUSE || runtime.GOOS == "windows" && errno == WSAEADDRINUSE {
				if nbrew.Scheme == "https://" {
					fmt.Println(server.Addr + " already in use")
					return nil
				}
				fmt.Println("http://" + server.Addr + "/admin/ already running")
				open("http://" + server.Addr + "/admin/")
				return nil
			} else {
				return err
			}
		}
		wait := make(chan os.Signal, 1)
		signal.Notify(wait, syscall.SIGINT, syscall.SIGTERM, syscall.SIGHUP)
		if nbrew.Scheme == "https://" {
			go http.ListenAndServe(":80", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != "GET" && r.Method != "HEAD" {
					http.Error(w, "Use HTTPS", http.StatusBadRequest)
					return
				}
				host, _, err := net.SplitHostPort(r.Host)
				if err != nil {
					host = r.Host
				} else {
					host = net.JoinHostPort(host, "443")
				}
				http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusFound)
			}))
			fmt.Printf(startmsg, server.Addr)
			go func() {
				err := server.ServeTLS(listener, "", "")
				if !errors.Is(err, http.ErrServerClosed) {
					fmt.Println(err)
					close(wait)
				}
			}()
		} else {
			// If we're running on localhost, we don't need to enforce strict
			// timeouts (makes debugging easier).
			server.ReadTimeout = 0
			server.WriteTimeout = 0
			server.IdleTimeout = 0
			fmt.Printf(startmsg, "http://"+server.Addr+"/admin/")
			go func() {
				err := server.Serve(listener)
				if !errors.Is(err, http.ErrServerClosed) {
					fmt.Println(err)
					close(wait)
				}
			}()
			open("http://" + server.Addr + "/admin/")
		}
		<-wait
		ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
		defer cancel()
		server.Shutdown(ctx)
		return nil
	}()
	if err != nil && !errors.Is(err, flag.ErrHelp) && !errors.Is(err, io.EOF) {
		fmt.Println(err)
		pressAnyKeyToExit()
		os.Exit(1)
	}
}

// static/dynamic private/public config:
// - static private: database.json, dns.json, s3.json, smtp.json (excluded)
// - static public: admin-folder.txt domain.txt, content-domain.txt, multisite.txt
// - dynamic private: captcha.json
// - dynamic public: allow-signup.txt, 503.html

func New(configFolder string) (*nb8.Notebrew, error) {
	var nbrew nb8.Notebrew
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	if configFolder == "" {
		XDGConfigHome := os.Getenv("XDG_CONFIG_HOME")
		if XDGConfigHome != "" {
			configFolder = filepath.Join(XDGConfigHome, "notebrew-config")
		} else {
			configFolder = filepath.Join(homeDir, "notebrew-config")
		}
	}
	configFolder, err = filepath.Abs(configFolder)
	if err != nil {
		return nil, err
	}
	nbrew.ConfigFS = os.DirFS(configFolder)

	b, err := os.ReadFile(filepath.Join(configFolder, "domain.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configFolder, "domain.txt"), err)
	}
	if len(b) > 0 {
		nbrew.Domain = string(b)
	} else {
		nbrew.Domain = "localhost:6444"
	}

	b, err = os.ReadFile(filepath.Join(configFolder, "content-domain.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configFolder, "content-domain.txt"), err)
	}
	if len(b) > 0 {
		nbrew.ContentDomain = string(b)
	} else {
		nbrew.ContentDomain = nbrew.Domain
	}

	b, err = os.ReadFile(filepath.Join(configFolder, "multisite.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configFolder, "multisite.txt"), err)
	}
	if len(b) > 0 {
		str := string(b)
		if str == "subdomain" || str == "subdirectory" {
			nbrew.Multisite = str
		}
	}

	b, err = os.ReadFile(filepath.Join(configFolder, "database.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configFolder, "database.json"), err)
	}
	if len(b) > 0 {
		var databaseConfig struct {
			Dialect  string            `json:"dialect,omitempty"`
			Filepath string            `json:"filepath,omitempty"`
			User     string            `json:"user,omitempty"`
			Password string            `json:"password,omitempty"`
			Host     string            `json:"host,omitempty"`
			Port     string            `json:"port,omitempty"`
			DBName   string            `json:"dbname,omitempty"`
			Params   map[string]string `json:"params,omitempty"`
		}
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&databaseConfig)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configFolder, "database.json"), err)
		}
		switch databaseConfig.Dialect {
		case "sqlite":
			if databaseConfig.Filepath == "" {
				return nil, fmt.Errorf("%s: sqlite: missing filepath field", filepath.Join(configFolder, "database.json"))
			}
			databaseConfig.Filepath, err = filepath.Abs(databaseConfig.Filepath)
			if err != nil {
				return nil, fmt.Errorf("%s: sqlite: %w", filepath.Join(configFolder, "database.json"), err)
			}
			dataSourceName := databaseConfig.Filepath + "?" + sqliteQueryString(databaseConfig.Params)
			nbrew.Dialect = "sqlite"
			nbrew.DB, err = sql.Open(sqliteDriverName, dataSourceName)
			if err != nil {
				return nil, fmt.Errorf("%s: sqlite: open %s: %w", filepath.Join(configFolder, "database.json"), dataSourceName, err)
			}
			err = nbrew.DB.Ping()
			if err != nil {
				return nil, fmt.Errorf("%s: sqlite: ping %s: %w", filepath.Join(configFolder, "database.json"), dataSourceName, err)
			}
			nbrew.ErrorCode = sqliteErrorCode
		case "postgres":
			values := make(url.Values)
			for key, value := range databaseConfig.Params {
				switch key {
				case "sslmode":
					values.Set(key, value)
				}
			}
			if _, ok := databaseConfig.Params["sslmode"]; !ok {
				values.Set("sslmode", "disable")
			}
			if databaseConfig.Port == "" {
				databaseConfig.Port = "5432"
			}
			uri := url.URL{
				Scheme:   "postgres",
				User:     url.UserPassword(databaseConfig.User, databaseConfig.Password),
				Host:     databaseConfig.Host + ":" + databaseConfig.Port,
				Path:     databaseConfig.DBName,
				RawQuery: values.Encode(),
			}
			dataSourceName := uri.String()
			nbrew.Dialect = "postgres"
			nbrew.DB, err = sql.Open("pgx", dataSourceName)
			if err != nil {
				return nil, fmt.Errorf("%s: postgres: open %s: %w", filepath.Join(configFolder, "database.json"), dataSourceName, err)
			}
			err = nbrew.DB.Ping()
			if err != nil {
				return nil, fmt.Errorf("%s: postgres: ping %s: %w", filepath.Join(configFolder, "database.json"), dataSourceName, err)
			}
			nbrew.ErrorCode = func(err error) string {
				var pgErr *pgconn.PgError
				if errors.As(err, &pgErr) {
					return pgErr.Code
				}
				return ""
			}
		case "mysql":
			values := make(url.Values)
			for key, value := range databaseConfig.Params {
				switch key {
				case "charset", "collation", "loc", "maxAllowedPacket",
					"readTimeout", "rejectReadOnly", "serverPubKey", "timeout",
					"tls", "writeTimeout", "connectionAttributes":
					values.Set(key, value)
				}
			}
			values.Set("multiStatements", "true")
			values.Set("parseTime", "true")
			if databaseConfig.Port == "" {
				databaseConfig.Port = "3306"
			}
			dataSourceName := fmt.Sprintf("%s:%s@tcp(%s:%s)/%s?%s", databaseConfig.User, databaseConfig.Password, databaseConfig.Host, databaseConfig.Password, databaseConfig.DBName, values.Encode())
			nbrew.Dialect = "mysql"
			nbrew.DB, err = sql.Open("mysql", dataSourceName)
			if err != nil {
				return nil, fmt.Errorf("%s: mysql: open %s: %w", filepath.Join(configFolder, "database.json"), dataSourceName, err)
			}
			err = nbrew.DB.Ping()
			if err != nil {
				return nil, fmt.Errorf("%s: mysql: ping %s: %w", filepath.Join(configFolder, "database.json"), dataSourceName, err)
			}
			nbrew.ErrorCode = func(err error) string {
				var mysqlErr *mysql.MySQLError
				if errors.As(err, &mysqlErr) {
					return strconv.FormatUint(uint64(mysqlErr.Number), 10)
				}
				return ""
			}
		case "":
			return nil, fmt.Errorf("%s: missing dialect field", filepath.Join(configFolder, "database.json"))
		default:
			return nil, fmt.Errorf("%s: unsupported dialect %q (possible values: sqlite, postgres, mysql)", filepath.Join(configFolder, "database.json"), databaseConfig.Dialect)
		}
	}

	b, err = os.ReadFile(filepath.Join(configFolder, "admin-folder.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configFolder, "admin-folder.txt"), err)
	}
	adminFolder := string(b)
	if adminFolder == "" {
		XDGDataHome := os.Getenv("XDG_DATA_HOME")
		if XDGDataHome != "" {
			adminFolder = filepath.Join(XDGDataHome, "notebrew-admin")
		} else {
			adminFolder = filepath.Join(homeDir, "notebrew-admin")
		}
	}
	if adminFolder == "database" {
		if nbrew.DB == nil {
			return nil, fmt.Errorf("%s: cannot use database as filesystem because %s is missing", filepath.Join(configFolder, "admin-folder.txt"), filepath.Join(configFolder, "database.json"))
		}
		b, err = os.ReadFile(filepath.Join(configFolder, "s3.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configFolder, "s3.json"), err)
		}
		if len(b) > 0 {
			var s3Config struct {
				Endpoint        string `json:"endpoint,omitempty"`
				Region          string `json:"region,omitempty"`
				Bucket          string `json:"bucket,omitempty"`
				AccessKeyID     string `json:"accessKeyID,omitempty"`
				SecretAccessKey string `json:"secretAccessKey,omitempty"`
			}
			decoder := json.NewDecoder(bytes.NewReader(b))
			decoder.DisallowUnknownFields()
			err := decoder.Decode(&s3Config)
			if err != nil {
				return nil, fmt.Errorf("%s: %w", filepath.Join(configFolder, "s3.json"), err)
			}
			if s3Config.Endpoint == "" {
				return nil, fmt.Errorf("%s: missing endpoint field", filepath.Join(configFolder, "s3.json"))
			}
			if s3Config.Region == "" {
				return nil, fmt.Errorf("%s: missing region field", filepath.Join(configFolder, "s3.json"))
			}
			if s3Config.Bucket == "" {
				return nil, fmt.Errorf("%s: missing bucket field", filepath.Join(configFolder, "s3.json"))
			}
			if s3Config.AccessKeyID == "" {
				return nil, fmt.Errorf("%s: missing accessKeyID field", filepath.Join(configFolder, "s3.json"))
			}
			if s3Config.SecretAccessKey == "" {
				return nil, fmt.Errorf("%s: missing secretAccessKey field", filepath.Join(configFolder, "s3.json"))
			}
			nbrew.FS = nb8.NewRemoteFS(nbrew.Dialect, nbrew.DB, nbrew.ErrorCode, &nb8.S3Storage{
				Client: s3.New(s3.Options{
					BaseEndpoint: aws.String(s3Config.Endpoint),
					Region:       s3Config.Region,
					Credentials:  aws.NewCredentialsCache(credentials.NewStaticCredentialsProvider(s3Config.AccessKeyID, s3Config.SecretAccessKey, "")),
				}),
				Bucket: s3Config.Bucket,
			})
		} else {
			b, err = os.ReadFile(filepath.Join(configFolder, "objects-folder.txt"))
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return nil, fmt.Errorf("%s: %w", filepath.Join(configFolder, "objects-folder.txt"), err)
			}
			objectsFolder := string(b)
			if objectsFolder == "" {
				XDGDataHome := os.Getenv("XDG_DATA_HOME")
				if XDGDataHome != "" {
					objectsFolder = filepath.Join(XDGDataHome, "notebrew-objects")
				} else {
					objectsFolder = filepath.Join(homeDir, "notebrew-objects")
				}
			}
			nbrew.FS = nb8.NewRemoteFS(nbrew.Dialect, nbrew.DB, nbrew.ErrorCode, nb8.NewFileStorage(objectsFolder, os.TempDir()))
		}
	} else {
		nbrew.FS = nb8.NewLocalFS(adminFolder, os.TempDir())
	}

	var dns01Solver acmez.Solver
	_ = dns01Solver
	b, err = os.ReadFile(filepath.Join(configFolder, "dns.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configFolder, "dns.json"), err)
	}
	if len(b) > 0 {
		var dns01Config struct {
			Provider  string `json:"provider,omitempty"`
			Username  string `json:"username,omitempty"`
			APIKey    string `json:"apiKey,omitempty"`
			APIToken  string `json:"apiToken,omitempty"`
			SecretKey string `json:"secretKey,omitempty"`
		}
		decoder := json.NewDecoder(bytes.NewReader(b))
		decoder.DisallowUnknownFields()
		err := decoder.Decode(&dns01Config)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", filepath.Join(configFolder, "dns.json"), err)
		}
		switch dns01Config.Provider {
		case "namecheap":
			if dns01Config.Username == "" {
				return nil, fmt.Errorf("%s: namecheap: missing username field", filepath.Join(configFolder, "dns.json"))
			}
			if dns01Config.APIKey == "" {
				return nil, fmt.Errorf("%s: namecheap: missing apiKey field", filepath.Join(configFolder, "dns.json"))
			}
			resp, err := http.Get("https://ipv4.icanhazip.com")
			if err != nil {
				return nil, fmt.Errorf("determining the IP address of this machine by calling https://ipv4.icanhazip.com: %w", err)
			}
			defer resp.Body.Close()
			var b strings.Builder
			_, err = io.Copy(&b, resp.Body)
			if err != nil {
				return nil, fmt.Errorf("https://ipv4.icanhazip.com: reading response body: %w", err)
			}
			clientIP := strings.TrimSpace(b.String())
			ip, err := netip.ParseAddr(clientIP)
			if err != nil {
				return nil, fmt.Errorf("could not determine IP address of the current machine: https://ipv4.icanhazip.com returned %q which is not an IP address", clientIP)
			}
			if !ip.Is4() {
				return nil, fmt.Errorf("the current machine's IP address (%s) is not IPv4: an IPv4 address is needed to integrate with namecheap's API", clientIP)
			}
			dns01Solver = &certmagic.DNS01Solver{
				DNSProvider: &namecheap.Provider{
					APIKey:      dns01Config.APIKey,
					User:        dns01Config.Username,
					APIEndpoint: "https://api.namecheap.com/xml.response",
					ClientIP:    clientIP,
				},
			}
		case "cloudflare":
			if dns01Config.APIToken == "" {
				return nil, fmt.Errorf("%s: cloudflare: missing apiToken field", filepath.Join(configFolder, "dns.json"))
			}
			dns01Solver = &certmagic.DNS01Solver{
				DNSProvider: &cloudflare.Provider{
					APIToken: dns01Config.APIToken,
				},
			}
		case "porkbun":
			if dns01Config.APIKey == "" {
				return nil, fmt.Errorf("%s: porkbun: missing apiKey field", filepath.Join(configFolder, "dns.json"))
			}
			if dns01Config.SecretKey == "" {
				return nil, fmt.Errorf("%s: porkbun: missing secretKey field", filepath.Join(configFolder, "dns.json"))
			}
			dns01Solver = &certmagic.DNS01Solver{
				DNSProvider: &porkbun.Provider{
					APIKey:       dns01Config.APIKey,
					APISecretKey: dns01Config.SecretKey,
				},
			}
		case "godaddy":
			if dns01Config.APIToken == "" {
				return nil, fmt.Errorf("%s: godaddy: missing apiToken field", filepath.Join(configFolder, "dns.json"))
			}
			dns01Solver = &certmagic.DNS01Solver{
				DNSProvider: &godaddy.Provider{
					APIToken: dns01Config.APIToken,
				},
			}
		case "":
			return nil, fmt.Errorf("%s: missing provider field", filepath.Join(configFolder, "dns.json"))
		default:
			return nil, fmt.Errorf("%s: unsupported provider %q (possible values: namecheap, cloudflare, porkbun, godaddy)", filepath.Join(configFolder, "dns.json"), dns01Config.Provider)
		}
	}

	return &nbrew, nil
}
