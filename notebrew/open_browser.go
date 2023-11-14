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
	switch runtime.GOOS {
	case "windows":
		startmsg = `
                     _       _
         _ __   ___ | |_ ___| |__  _ __ _____      __
        | '_ \ / _ \| __/ _ \ '_ \| '__/ _ \ \ /\ / /
        | | | | (_) | ||  __/ |_) | | |  __/\ V  V /
        |_| |_|\___/ \__\___|_.__/|_|  \___| \_/\_/

     notebrew is running on %s

  Please do not close this window (except to quit notebrew).
`
	case "darwin":
		startmsg = `
                     _       _
         _ __   ___ | |_ ___| |__  _ __ _____      __
        | '_ \ / _ \| __/ _ \ '_ \| '__/ _ \ \ /\ / /
        | | | | (_) | ||  __/ |_) | | |  __/\ V  V /
        |_| |_|\___/ \__\___|_.__/|_|  \___| \_/\_/

     notebrew is running on %s

  Press Ctrl+C (not Cmd+C) to exit. If you close this window
 without exiting, notebrew will keep running in the background
     (run the command "notebrew stop" to stop notebrew).
`
	default:
		startmsg = `
                     _       _
         _ __   ___ | |_ ___| |__  _ __ _____      __
        | '_ \ / _ \| __/ _ \ '_ \| '__/ _ \ \ /\ / /
        | | | | (_) | ||  __/ |_) | | |  __/\ V  V /
        |_| |_|\___/ \__\___|_.__/|_|  \___| \_/\_/

     notebrew is running on %s

   Press Ctrl+C to exit. If you close this window without
    exiting, notebrew will keep running in the background
     (run the command "notebrew stop" to stop notebrew).
`
	}
}
