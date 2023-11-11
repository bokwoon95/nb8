//go:build !windows

package main

// pressAnyKeyToExit is a no-op on non-windows platforms because macOS and
// Linux keep the terminal open after a command exits, so we don't have to
// artificially keep the terminal open by waiting for the user to press a key
// before exiting.
func pressAnyKeyToExit() {}
