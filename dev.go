//go:build dev
// +build dev

package nb8

import (
	"os"
)

func init() {
	rootFS = os.DirFS(".")
}
