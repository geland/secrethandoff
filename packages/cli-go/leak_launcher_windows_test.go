//go:build windows

package main

import (
	"os"
	"testing"
)

// writeLauncher writes a batch file that runs the test binary's browser
// helper. The page URL contains no characters that cmd treats as special.
func writeLauncher(t *testing.T, path, self string) string {
	t.Helper()
	script := "@echo off\r\nset SECRETHANDOFF_HELPER_URL_ARG=%~1\r\n\"" + self + "\" -test.run=^^TestLeakHelperBrowser$\r\n"
	path += ".cmd"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}
