package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/bokwoon95/nb8"
	_ "github.com/denisenkom/go-mssqldb"
	_ "github.com/go-sql-driver/mysql"
	_ "github.com/lib/pq"
)

type DatabaseConfig struct {
	Dialect  string `json:"dialect,omitempty"`
	Filepath string `json:"filepath,omitempty"`
	User     string `json:"user,omitempty"`
	Password string `json:"password,omitempty"`
	Host     string `json:"host,omitempty"`
	Port     string `json:"port,omitempty"`
	DBName   string `json:"dbname,omitempty"`
	// TODO: Add our own params like sslmode=disable or parseTime=true
	// depending on the dialect if the user hasn't already set them.
	Params map[string]string `json:"params,omitempty"`
}

type DNS01Config struct {
	Provider  string `json:"provider,omitempty"`
	Username  string `json:"username,omitempty"`
	APIKey    string `json:"apiKey,omitempty"`
	APIToken  string `json:"apiToken,omitempty"`
	SecretKey string `json:"secretKey,omitempty"`
}

type SMTPConfig struct {
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Host     string `json:"host,omitempty"`
	Port     string `json:"port,omitempty"`
}

type S3Config struct {
	Endpoint        string `json:"endpoint,omitempty"`
	Region          string `json:"region,omitempty"`
	Bucket          string `json:"bucket,omitempty"`
	AccessKeyID     string `json:"accessKeyID,omitempty"`
	SecretAccessKey string `json:"secretAccessKey,omitempty"`
}

type CaptchaConfig struct {
	SecretKey string `json:"secretKey,omitempty"`
	SiteKey   string `json:"siteKey,omitempty"`
}

// static/dynamic private/public config:
// - static private: database.json, dns01.json, smtp.json, s3.json
// - static public: admin-folder.txt domain.txt, content-domain.txt, multisite.txt
// - dynamic private: captcha.json
// - dynamic public: allow-signup.txt

func main() {
	err := func() error {
		var configFolder string
		flagset := flag.NewFlagSet("", flag.ContinueOnError)
		flagset.StringVar(&configFolder, "config-folder", "", "")
		err := flagset.Parse(os.Args[1:])
		if err != nil {
			return err
		}
		if configFolder == "" {
			configFolder = os.Getenv("XDG_CONFIG_HOME")
		}
		return nil
	}()
	if err != nil && !errors.Is(err, flag.ErrHelp) && !errors.Is(err, io.EOF) {
		fmt.Println(err)
		pressAnyKeyToExit()
		os.Exit(1)
	}
}

func NewNotebrew() (*nb8.Notebrew, error) {
	nbrew := &nb8.Notebrew{}
	return nbrew, nil
}
