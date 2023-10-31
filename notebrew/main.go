package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/bokwoon95/nb8"
)

func main() {
	err := func() error {
		return nil
	}()
	if err != nil && !errors.Is(err, flag.ErrHelp) && !errors.Is(err, io.EOF) {
		fmt.Println(err)
		pressAnyKeyToExit()
		os.Exit(1)
	}
}

func NewNotebrew() (*nb8.Notebrew, error) {
	nbrew := &nb8.Notebrew{
	}
	return nbrew, nil
}
