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

// static/dynamic private/public config:
// - static private: database.json, dns.json, s3.json, smtp.json (excluded)
// - static public: files.txt domain.txt, contentdomain.txt, multisite.txt
// - dynamic private: captcha.json
// - dynamic public: allowsignup.txt, 503.html

func main() {
	// Wrap everything in an anonymous function so we can call os.Exit while
	// still allowing all deferred functions to complete.
	//
	// https://stackoverflow.com/questions/27629380/how-to-exit-a-go-program-honoring-deferred-calls
	err := func() error {
		homeDir, err := os.UserHomeDir()
		if err != nil {
			return err
		}
		configHome := os.Getenv("XDG_CONFIG_HOME")
		if configHome == "" {
			configHome = homeDir
		}
		dataHome := os.Getenv("XDG_DATA_HOME")
		if dataHome == "" {
			dataHome = homeDir
		}
		var configfolder string
		flagset := flag.NewFlagSet("", flag.ContinueOnError)
		flagset.StringVar(&configfolder, "configfolder", "", "")
		err = flagset.Parse(os.Args[1:])
		if err != nil {
			return err
		}
		if configfolder == "" {
			configfolder = filepath.Join(configHome, "notebrew-config")
			err := os.MkdirAll(configfolder, 0755)
			if err != nil {
				return err
			}
		} else {
			configfolder = filepath.Clean(configfolder)
			_, err := os.Stat(configfolder)
			if err != nil {
				return err
			}
		}
		nbrew := &nb8.Notebrew{
			ConfigFS: os.DirFS(configfolder),
			Logger: slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{
				AddSource: true,
			})),
		}

		var addr string
		b, err := os.ReadFile(filepath.Join(configfolder, "port.txt"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configfolder, "port.txt"), err)
		}
		nbrew.Port = string(bytes.TrimSpace(b))

		b, err = os.ReadFile(filepath.Join(configfolder, "domain.txt"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configfolder, "domain.txt"), err)
		}
		nbrew.Domain = string(bytes.TrimSpace(b))

		if nbrew.Port != "" {
			if nbrew.Port == "443" || nbrew.Port == "80" {
				addr = ":" + nbrew.Port
			} else {
				addr = "localhost:" + nbrew.Port
			}
			if nbrew.Domain != "" {
				nbrew.Scheme = "https://"
			} else {
				nbrew.Scheme = "http://"
				nbrew.Domain = "localhost:" + nbrew.Port
			}
		} else {
			if nbrew.Domain != "" {
				addr = ":443"
				nbrew.Scheme = "https://"
			} else {
				addr = "localhost:6444"
				nbrew.Scheme = "http://"
				nbrew.Domain = "localhost:6444"
			}
		}

		b, err = os.ReadFile(filepath.Join(configfolder, "contentdomain.txt"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configfolder, "contentdomain.txt"), err)
		}
		nbrew.ContentDomain = string(bytes.TrimSpace(b))
		if nbrew.ContentDomain == "" {
			nbrew.ContentDomain = nbrew.Domain
		}

		b, err = os.ReadFile(filepath.Join(configfolder, "database.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configfolder, "database.json"), err)
		}
		b = bytes.TrimSpace(b)
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
				return fmt.Errorf("%s: %w", filepath.Join(configfolder, "database.json"), err)
			}
			switch databaseConfig.Dialect {
			case "sqlite":
				if databaseConfig.Filepath == "" {
					databaseConfig.Filepath = filepath.Join(dataHome, "notebrew-database.sqlite")
				}
				databaseConfig.Filepath, err = filepath.Abs(databaseConfig.Filepath)
				if err != nil {
					return fmt.Errorf("%s: sqlite: %w", filepath.Join(configfolder, "database.json"), err)
				}
				dataSourceName := databaseConfig.Filepath + "?" + sqliteQueryString(databaseConfig.Params)
				nbrew.Dialect = "sqlite"
				nbrew.DB, err = sql.Open(sqliteDriverName, dataSourceName)
				if err != nil {
					return fmt.Errorf("%s: sqlite: open %s: %w", filepath.Join(configfolder, "database.json"), dataSourceName, err)
				}
				err = nbrew.DB.Ping()
				if err != nil {
					return fmt.Errorf("%s: sqlite: ping %s: %w", filepath.Join(configfolder, "database.json"), dataSourceName, err)
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
					return fmt.Errorf("%s: postgres: open %s: %w", filepath.Join(configfolder, "database.json"), dataSourceName, err)
				}
				err = nbrew.DB.Ping()
				if err != nil {
					return fmt.Errorf("%s: postgres: ping %s: %w", filepath.Join(configfolder, "database.json"), dataSourceName, err)
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
					return fmt.Errorf("%s: mysql: open %s: %w", filepath.Join(configfolder, "database.json"), config.FormatDSN(), err)
				}
				err = nbrew.DB.Ping()
				if err != nil {
					return fmt.Errorf("%s: mysql: ping %s: %w", filepath.Join(configfolder, "database.json"), config.FormatDSN(), err)
				}
				nbrew.ErrorCode = func(err error) string {
					var mysqlErr *mysql.MySQLError
					if errors.As(err, &mysqlErr) {
						return strconv.FormatUint(uint64(mysqlErr.Number), 10)
					}
					return ""
				}
			case "":
				return fmt.Errorf("%s: missing dialect field", filepath.Join(configfolder, "database.json"))
			default:
				return fmt.Errorf("%s: unsupported dialect %q (possible values: sqlite, postgres, mysql)", filepath.Join(configfolder, "database.json"), databaseConfig.Dialect)
			}
			err = nb8.Automigrate(nbrew.Dialect, nbrew.DB)
			if err != nil {
				return err
			}
		}

		b, err = os.ReadFile(filepath.Join(configfolder, "files.txt"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configfolder, "files.txt"), err)
		}
		filesfolder := string(bytes.TrimSpace(b))
		if filesfolder == "" {
			filesfolder = filepath.Join(dataHome, "notebrew-files")
			err := os.MkdirAll(filesfolder, 0755)
			if err != nil {
				return err
			}
			nbrew.FS = nb8.NewLocalFS(filesfolder, os.TempDir())
		} else if filesfolder == "database" {
			if nbrew.DB == nil {
				return fmt.Errorf("%s: cannot use database as filesystem because %s is missing", filepath.Join(configfolder, "files.txt"), filepath.Join(configfolder, "database.json"))
			}
			b, err = os.ReadFile(filepath.Join(configfolder, "s3.json"))
			if err != nil && !errors.Is(err, fs.ErrNotExist) {
				return fmt.Errorf("%s: %w", filepath.Join(configfolder, "s3.json"), err)
			}
			b = bytes.TrimSpace(b)
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
					return fmt.Errorf("%s: %w", filepath.Join(configfolder, "s3.json"), err)
				}
				if s3Config.Endpoint == "" {
					return fmt.Errorf("%s: missing endpoint field", filepath.Join(configfolder, "s3.json"))
				}
				if s3Config.Region == "" {
					return fmt.Errorf("%s: missing region field", filepath.Join(configfolder, "s3.json"))
				}
				if s3Config.Bucket == "" {
					return fmt.Errorf("%s: missing bucket field", filepath.Join(configfolder, "s3.json"))
				}
				if s3Config.AccessKeyID == "" {
					return fmt.Errorf("%s: missing accessKeyID field", filepath.Join(configfolder, "s3.json"))
				}
				if s3Config.SecretAccessKey == "" {
					return fmt.Errorf("%s: missing secretAccessKey field", filepath.Join(configfolder, "s3.json"))
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
				b, err = os.ReadFile(filepath.Join(configfolder, "objectsfolder.txt"))
				if err != nil && !errors.Is(err, fs.ErrNotExist) {
					return fmt.Errorf("%s: %w", filepath.Join(configfolder, "objectsfolder.txt"), err)
				}
				objectsfolder := string(bytes.TrimSpace(b))
				if objectsfolder == "" {
					objectsfolder = filepath.Join(dataHome, "notebrew-objects")
					err := os.MkdirAll(objectsfolder, 0755)
					if err != nil {
						return err
					}
				} else {
					objectsfolder = path.Clean(objectsfolder)
					_, err := os.Stat(objectsfolder)
					if err != nil {
						return err
					}
				}
				nbrew.FS = nb8.NewRemoteFS(nbrew.Dialect, nbrew.DB, nbrew.ErrorCode, nb8.NewFileStorage(objectsfolder, os.TempDir()))
			}
		} else {
			filesfolder = filepath.Clean(filesfolder)
			_, err := os.Stat(filesfolder)
			if err != nil {
				return err
			}
			nbrew.FS = nb8.NewLocalFS(filesfolder, os.TempDir())
		}
		dirs := []string{
			"notes",
			"output",
			"output/posts",
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
			// TODO: cmd, err := notebrewcli.Command(args[0], args[1]...); err := cmd.Run()
			_ = args
			switch command {
			default:
				return fmt.Errorf("unknown command %s", command)
			}
		}

		var dns01Solver acmez.Solver
		b, err = os.ReadFile(filepath.Join(configfolder, "dns.json"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configfolder, "dns.json"), err)
		}
		b = bytes.TrimSpace(b)
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
				return fmt.Errorf("%s: %w", filepath.Join(configfolder, "dns.json"), err)
			}
			switch dnsConfig.Provider {
			case "namecheap":
				if dnsConfig.Username == "" {
					return fmt.Errorf("%s: namecheap: missing username field", filepath.Join(configfolder, "dns.json"))
				}
				if dnsConfig.APIKey == "" {
					return fmt.Errorf("%s: namecheap: missing apiKey field", filepath.Join(configfolder, "dns.json"))
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
					return fmt.Errorf("%s: cloudflare: missing apiToken field", filepath.Join(configfolder, "dns.json"))
				}
				dns01Solver = &certmagic.DNS01Solver{
					DNSProvider: &cloudflare.Provider{
						APIToken: dnsConfig.APIToken,
					},
				}
			case "porkbun":
				if dnsConfig.APIKey == "" {
					return fmt.Errorf("%s: porkbun: missing apiKey field", filepath.Join(configfolder, "dns.json"))
				}
				if dnsConfig.SecretKey == "" {
					return fmt.Errorf("%s: porkbun: missing secretKey field", filepath.Join(configfolder, "dns.json"))
				}
				dns01Solver = &certmagic.DNS01Solver{
					DNSProvider: &porkbun.Provider{
						APIKey:       dnsConfig.APIKey,
						APISecretKey: dnsConfig.SecretKey,
					},
				}
			case "godaddy":
				if dnsConfig.APIToken == "" {
					return fmt.Errorf("%s: godaddy: missing apiToken field", filepath.Join(configfolder, "dns.json"))
				}
				dns01Solver = &certmagic.DNS01Solver{
					DNSProvider: &godaddy.Provider{
						APIToken: dnsConfig.APIToken,
					},
				}
			case "":
				return fmt.Errorf("%s: missing provider field", filepath.Join(configfolder, "dns.json"))
			default:
				return fmt.Errorf("%s: unsupported provider %q (possible values: namecheap, cloudflare, porkbun, godaddy)", filepath.Join(configfolder, "dns.json"), dnsConfig.Provider)
			}
		}

		b, err = os.ReadFile(filepath.Join(configfolder, "certmagic.txt"))
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return fmt.Errorf("%s: %w", filepath.Join(configfolder, "certmagic.txt"), err)
		}
		certfolder := string(bytes.TrimSpace(b))
		if certfolder == "" {
			certfolder = filepath.Join(configfolder, "certmagic")
			err := os.MkdirAll(certfolder, 0755)
			if err != nil {
				return err
			}
		} else {
			certfolder = filepath.Clean(certfolder)
			_, err := os.Stat(certfolder)
			if err != nil {
				return err
			}
		}
		certStorage := &certmagic.FileStorage{
			Path: certfolder,
		}

		// Create a new server (this step will provision the HTTPS
		// certificates, if it fails an error will be returned).
		server, err := nbrew.NewServer(&nb8.ServerConfig{
			Addr:        addr,
			DNS01Solver: dns01Solver,
			CertStorage: certStorage,
		})
		if err != nil {
			return err
		}

		// Manually acquire a listener instead of using the more convenient
		// ListenAndServe() just so that we can report back to the user if the
		// port is already in use.
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
				if server.Addr == "localhost" || strings.HasPrefix(server.Addr, "localhost:") {
					fmt.Println("notebrew is already running on http://" + server.Addr + "/files/")
					open("http://" + server.Addr + "/files/")
					return nil
				}
				fmt.Println("notebrew is already running (run `notebrew stop` to stop the process)")
				return nil
			}
			return err
		}

		// Swallow SIGHUP so that we can keep running even when the (SSH)
		// session ends (the user should use `notebrew stop` to stop the
		// process).
		ch := make(chan os.Signal, 1)
		signal.Notify(ch, syscall.SIGHUP)
		go func() {
			for {
				<-ch
			}
		}()

		wait := make(chan os.Signal, 1)
		signal.Notify(wait, syscall.SIGINT, syscall.SIGTERM)
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
			fmt.Printf(startmsg, "http://"+server.Addr+"/files/")
			go func() {
				err := server.Serve(listener)
				if !errors.Is(err, http.ErrServerClosed) {
					fmt.Println(err)
					close(wait)
				}
			}()
			open("http://" + server.Addr + "/files/")
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
