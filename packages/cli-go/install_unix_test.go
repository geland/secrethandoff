//go:build !windows

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestShellPathIsQuotedAndFirst(t *testing.T) {
	home := t.TempDir()
	bin := filepath.Join(home, "space's $(touch injected) bin")
	if err := persistShellPath(home, "sh", "", "", bin, false, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	profile := filepath.Join(home, ".profile")
	for _, shell := range []string{"sh", "bash", "zsh"} {
		t.Run(shell, func(t *testing.T) {
			path, err := exec.LookPath(shell)
			if err != nil {
				t.Skip("shell unavailable")
			}
			cmd := exec.Command(path, "-c", `. "$1"; . "$1"; printf '%s' "$PATH"`, "test", profile)
			cmd.Dir = home
			cmd.Env = []string{"PATH=/usr/bin:/bin:" + bin}
			out, err := cmd.CombinedOutput()
			if err != nil || string(out) != bin+":/usr/bin:/bin:"+bin {
				t.Fatalf("PATH %q: %v", out, err)
			}
			if _, err := os.Stat(filepath.Join(home, "injected")); !os.IsNotExist(err) {
				t.Fatal("profile executed path text")
			}
		})
	}
}

func TestPathEditRetainsDotfileSymlinkAndPermissions(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "dotfiles-profile")
	link := filepath.Join(dir, ".profile")
	os.WriteFile(target, []byte("# user's profile\n"), 0o600)
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if err := updatePathFile(link, "# test block\n", false); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(link)
	if err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatal("replaced symlink")
	}
	info, err = os.Stat(target)
	if err != nil || info.Mode().Perm() != 0o600 {
		t.Fatal("changed profile permissions")
	}
	b, _ := os.ReadFile(target)
	if !strings.HasPrefix(string(b), "# user's profile\n") {
		t.Fatal("lost profile text")
	}
}
