//go:build !windows

package main

import (
	"io"
	"os"
)

func persistUserPath(home, dir string, dry bool, out io.Writer) error {
	return persistShellPath(home, os.Getenv("SHELL"), os.Getenv("ZDOTDIR"), os.Getenv("XDG_CONFIG_HOME"), dir, dry, out)
}
