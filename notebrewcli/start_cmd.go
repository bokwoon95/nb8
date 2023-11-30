package notebrewcli

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bokwoon95/nb8"
	"github.com/bokwoon95/sq"
	"github.com/caddyserver/certmagic"
	"github.com/klauspost/cpuid/v2"
	"github.com/libdns/cloudflare"
	"github.com/libdns/godaddy"
	"github.com/libdns/namecheap"
	"github.com/libdns/porkbun"
	"github.com/mholt/acmez"
)

type StartCmd struct {
}

func NewServer(nbrew *nb8.Notebrew, configfolder, addr string) (*http.Server, error) {
	if nbrew.Domain == "" {
		return nil, fmt.Errorf("Domain cannot be empty")
	}
	if nbrew.ContentDomain == "" {
		return nil, fmt.Errorf("ContentDomain cannot be empty")
	}
	server := &http.Server{
		Addr:    addr,
		Handler: nbrew,
	}
	if addr != ":443" {
		return server, nil
	}
	server.ReadTimeout = 60 * time.Second
	server.WriteTimeout = 60 * time.Second
	server.IdleTimeout = 120 * time.Second

	var dns01Solver acmez.Solver
	b, err := os.ReadFile(filepath.Join(configfolder, "dns.json"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configfolder, "dns.json"), err)
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
			return nil, fmt.Errorf("%s: %w", filepath.Join(configfolder, "dns.json"), err)
		}
		switch dnsConfig.Provider {
		case "namecheap":
			if dnsConfig.Username == "" {
				return nil, fmt.Errorf("%s: namecheap: missing username field", filepath.Join(configfolder, "dns.json"))
			}
			if dnsConfig.APIKey == "" {
				return nil, fmt.Errorf("%s: namecheap: missing apiKey field", filepath.Join(configfolder, "dns.json"))
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
			err = resp.Body.Close()
			if err != nil {
				return nil, err
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
					APIKey:      dnsConfig.APIKey,
					User:        dnsConfig.Username,
					APIEndpoint: "https://api.namecheap.com/xml.response",
					ClientIP:    clientIP,
				},
			}
		case "cloudflare":
			if dnsConfig.APIToken == "" {
				return nil, fmt.Errorf("%s: cloudflare: missing apiToken field", filepath.Join(configfolder, "dns.json"))
			}
			dns01Solver = &certmagic.DNS01Solver{
				DNSProvider: &cloudflare.Provider{
					APIToken: dnsConfig.APIToken,
				},
			}
		case "porkbun":
			if dnsConfig.APIKey == "" {
				return nil, fmt.Errorf("%s: porkbun: missing apiKey field", filepath.Join(configfolder, "dns.json"))
			}
			if dnsConfig.SecretKey == "" {
				return nil, fmt.Errorf("%s: porkbun: missing secretKey field", filepath.Join(configfolder, "dns.json"))
			}
			dns01Solver = &certmagic.DNS01Solver{
				DNSProvider: &porkbun.Provider{
					APIKey:       dnsConfig.APIKey,
					APISecretKey: dnsConfig.SecretKey,
				},
			}
		case "godaddy":
			if dnsConfig.APIToken == "" {
				return nil, fmt.Errorf("%s: godaddy: missing apiToken field", filepath.Join(configfolder, "dns.json"))
			}
			dns01Solver = &certmagic.DNS01Solver{
				DNSProvider: &godaddy.Provider{
					APIToken: dnsConfig.APIToken,
				},
			}
		case "":
			return nil, fmt.Errorf("%s: missing provider field", filepath.Join(configfolder, "dns.json"))
		default:
			return nil, fmt.Errorf("%s: unsupported provider %q (possible values: namecheap, cloudflare, porkbun, godaddy)", filepath.Join(configfolder, "dns.json"), dnsConfig.Provider)
		}
	}

	b, err = os.ReadFile(filepath.Join(configfolder, "certmagic.txt"))
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return nil, fmt.Errorf("%s: %w", filepath.Join(configfolder, "certmagic.txt"), err)
	}
	certfolder := string(bytes.TrimSpace(b))
	if certfolder == "" {
		certfolder = filepath.Join(configfolder, "certmagic")
		err := os.MkdirAll(certfolder, 0755)
		if err != nil {
			return nil, err
		}
	} else {
		certfolder = filepath.Clean(certfolder)
		_, err := os.Stat(certfolder)
		if err != nil {
			return nil, err
		}
	}
	certStorage := &certmagic.FileStorage{
		Path: certfolder,
	}

	// staticCertConfig manages the certificate for the main domain, content domain
	// and wildcard subdomain.
	staticCertConfig := certmagic.NewDefault()
	staticCertConfig.Storage = certStorage
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
	var domains []string
	if nbrew.Domain == nbrew.ContentDomain {
		domains = append(domains, nbrew.Domain, "www."+nbrew.Domain, "cdn."+nbrew.Domain)
	} else {
		domains = append(domains, nbrew.Domain, "www."+nbrew.Domain, "cdn."+nbrew.ContentDomain, nbrew.ContentDomain, "www."+nbrew.ContentDomain)
	}
	if dns01Solver != nil {
		domains = append(domains, "*."+nbrew.ContentDomain)
	}
	fmt.Printf("notebrew static domains: %v\n", strings.Join(domains, ", "))
	err = staticCertConfig.ManageSync(context.Background(), domains)
	if err != nil {
		return nil, err
	}

	// dynamicCertConfig manages the certificates for custom domains.
	//
	// If dns01Solver hasn't been configured, dynamicCertConfig will
	// also be responsible for getting the certificates for subdomains.
	// This approach will not scale and might end up getting rate
	// limited by Let's Encrypt (50 certificates per week). The safest
	// way to avoid being rate limited is to configure dns01Solver so
	// that the wildcard certificate is available.
	dynamicCertConfig := certmagic.NewDefault()
	dynamicCertConfig.Storage = certStorage
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

	server.TLSConfig = &tls.Config{
		NextProtos: []string{"h2", "http/1.1", "acme-tls/1"},
		GetCertificate: func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if clientHello.ServerName == "" {
				return nil, fmt.Errorf("server name empty")
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
