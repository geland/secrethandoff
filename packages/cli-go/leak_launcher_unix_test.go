//go:build !windows

package main

import (
	"os"
	"testing"
)

// writeLauncher writes a script that runs the test binary's browser helper.
func writeLauncher(t *testing.T, path, self string) string {
	t.Helper()
	script := "#!/bin/sh\nSECRETHANDOFF_HELPER_URL_ARG=\"$1\" exec \"" + self + "\" -test.run='^TestLeakHelperBrowser$'\n"
	if err := os.WriteFile(path, []byte(script), 0o700); err != nil {
		t.Fatal(err)
	}
	return path
}
