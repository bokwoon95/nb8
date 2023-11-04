//go:build open_browser
// +build open_browser

package main

import (
	"os/exec"
	"runtime"
)

func init() {
	open = func(address string) {
		switch runtime.GOOS {
		case "windows":
			exec.Command("explorer.exe", address).Run()
		case "darwin":
			exec.Command("open", address).Run()
		default:
			exec.Command("xdg-open", address).Run()
		}
	}
}
