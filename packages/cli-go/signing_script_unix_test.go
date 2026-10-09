//go:build !windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// Exercise the orchestration with fake signing tools, never real credentials.
// A successful notarytool process alone must not authorize release packaging.
func TestMacSigningRequiresAcceptedNotarization(t *testing.T) {
	for _, status := range []string{"Accepted", "Invalid", "In Progress"} {
		t.Run(status, func(t *testing.T) {
			root := t.TempDir()
			scripts := filepath.Join(root, "scripts")
			tools := filepath.Join(root, "tools")
			temp := filepath.Join(root, "temp")
			for _, d := range []string{scripts, tools, temp} {
				if err := os.Mkdir(d, 0700); err != nil {
					t.Fatal(err)
				}
			}
			src, err := os.ReadFile("scripts/sign-macos.sh")
			if err != nil {
				t.Fatal(err)
			}
			script := filepath.Join(scripts, "sign-macos.sh")
			if err := os.WriteFile(script, src, 0700); err != nil {
				t.Fatal(err)
			}
			mocks := map[string]string{
				"security": "exit 0\n",
				"codesign": "exit 0\n",
				"ditto":    "exit 0\n",
				"uuidgen":  "printf 'dummy-test-password'\n",
				"xcrun":    "printf '{\"status\":\"%s\"}' \"$TEST_NOTARY_STATUS\"\n",
				"plutil":   "sed -n 's/.*\"status\":\"\\([^\"]*\\)\".*/\\1/p' \"$6\"\n",
			}
			for name, body := range mocks {
				if err := os.WriteFile(filepath.Join(tools, name), []byte("#!/bin/sh\n"+body), 0700); err != nil {
					t.Fatal(err)
				}
			}
			cmd := exec.Command("/bin/bash", script)
			cmd.Env = []string{"PATH=" + tools + ":/usr/bin:/bin", "RUNNER_TEMP=" + temp,
				"APPLE_CERT_P12_BASE64=dGVzdA==", "APPLE_CERT_PASSWORD=dummy", "APPLE_SIGNING_IDENTITY=dummy",
				"APPLE_API_KEY_P8_BASE64=dGVzdA==", "APPLE_API_KEY_ID=dummy", "APPLE_API_ISSUER_ID=dummy",
				"TEST_NOTARY_STATUS=" + status}
			out, err := cmd.CombinedOutput()
			if status == "Accepted" {
				if err != nil || strings.Count(string(out), "notarization accepted") != 2 {
					t.Fatalf("accepted candidate: %v: %s", err, out)
				}
			} else if err == nil || !strings.Contains(string(out), "was not accepted") {
				t.Fatalf("unaccepted candidate was not rejected: %v: %s", err, out)
			}
			entries, err := os.ReadDir(temp)
			if err != nil || len(entries) != 0 {
				t.Fatalf("signing temporary files retained: %v", err)
			}
		})
	}
}
