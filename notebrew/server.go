package main

import (
	"fmt"
	"net/http"

	"github.com/bokwoon95/nb8"
)

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
	return nil, nil
}
