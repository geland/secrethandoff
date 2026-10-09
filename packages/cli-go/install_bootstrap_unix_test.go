//go:build !windows

package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestBootstrapDelegatesAndPropagatesFailure(t *testing.T) {
	for _, tc := range []struct {
		name, setupExit    string
		binaryOnly, tamper bool
		marketplace        bool
		wantCode           int
	}{
		{"default-binary-only", "0", true, false, false, 0},
		{"marketplace", "0", false, false, true, 0}, {"binary-only", "0", true, false, true, 0},
		{"setup-failure", "7", false, false, true, 7}, {"bad-checksum", "0", false, true, true, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			bin := filepath.Join(dir, "tools")
			os.Mkdir(bin, 0o755)
			body := []byte("#!/bin/sh\nprintf '%s\\n' \"$@\" > \"$FAKE_CALL_LOG\"\nexit \"$FAKE_SETUP_EXIT\"\n")
			var archive bytes.Buffer
			gz := gzip.NewWriter(&archive)
			tw := tar.NewWriter(gz)
			if err := tw.WriteHeader(&tar.Header{Name: "secrethandoff", Mode: 0o755, Size: int64(len(body))}); err != nil {
				t.Fatal(err)
			}
			tw.Write(body)
			tw.Close()
			gz.Close()
			os.WriteFile(filepath.Join(dir, "archive"), archive.Bytes(), 0o644)
			hash := fmt.Sprintf("%x", sha256.Sum256(archive.Bytes()))
			if tc.tamper {
				hash = strings.Repeat("0", 64)
			}
			name := fmt.Sprintf("secrethandoff_0.0.1_%s_%s.tar.gz", runtime.GOOS, runtime.GOARCH)
			os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(hash+"  "+name+"\n"), 0o644)
			curl := `#!/bin/sh
while [ "$#" -gt 0 ]; do
  case "$1" in -o) shift; dest="$1" ;; http*) url="$1" ;; esac
  shift
done
case "$url" in */SHA256SUMS) cp "$FAKE_FIXTURE/SHA256SUMS" "$dest" ;; *) cp "$FAKE_FIXTURE/archive" "$dest" ;; esac
`
			os.WriteFile(filepath.Join(bin, "curl"), []byte(curl), 0o755)
			script, _ := filepath.Abs(filepath.Join("..", "..", "public", "install.sh"))
			cmd := exec.Command("/bin/sh", script)
			log := filepath.Join(dir, "calls")
			cmd.Env = []string{"PATH=" + bin + ":/usr/bin:/bin", "SECRETHANDOFF_VERSION=0.0.1", "SECRETHANDOFF_DOWNLOAD_URL=https://fixture.invalid/release", "SECRETHANDOFF_BIN_DIR=" + filepath.Join(dir, "destination with spaces"), "FAKE_FIXTURE=" + dir, "FAKE_CALL_LOG=" + log, "FAKE_SETUP_EXIT=" + tc.setupExit}
			if tc.marketplace {
				cmd.Env = append(cmd.Env, "SECRETHANDOFF_MARKETPLACE=owner/repo")
			}
			if tc.binaryOnly && tc.marketplace {
				cmd.Env = append(cmd.Env, "SECRETHANDOFF_NO_SETUP=1")
			}
			out, err := cmd.CombinedOutput()
			code := 0
			if err != nil {
				if exit, ok := err.(*exec.ExitError); ok {
					code = exit.ExitCode()
				} else {
					t.Fatal(err)
				}
			}
			if code != tc.wantCode {
				t.Fatalf("exit %d: %s", code, out)
			}
			args, err := os.ReadFile(log)
			if tc.tamper {
				if !os.IsNotExist(err) {
					t.Fatal("executed binary with wrong checksum")
				}
				return
			}
			if err != nil || !strings.HasPrefix(string(args), "setup\n--no-init\n--bin-dir\n") {
				t.Fatalf("setup argv %s: %v", args, err)
			}
			if strings.Contains(string(args), "--marketplace\nowner/repo\n") != tc.marketplace {
				t.Fatal(string(args))
			}
			if strings.Contains(string(args), "--binary-only") != tc.binaryOnly {
				t.Fatal(string(args))
			}
		})
	}
}
