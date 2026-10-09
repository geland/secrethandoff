package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const pathStart = "# >>> secrethandoff PATH >>>"
const pathEnd = "# <<< secrethandoff PATH <<<"

func quoteShell(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }

func persistShellPath(home, shell, zdir, configDir, dir string, dry bool, out io.Writer) error {
	q := quoteShell(dir)
	body := "case \"${PATH}\" in\n  " + q + "|" + q + ":*) ;;\n  *) export PATH=" + q + ":\"${PATH}\" ;;\nesac\n"
	var files []string
	switch filepath.Base(shell) {
	case "zsh":
		if zdir == "" {
			zdir = home
		}
		files = []string{filepath.Join(zdir, ".zprofile"), filepath.Join(zdir, ".zshrc")}
	case "bash":
		login := filepath.Join(home, ".profile")
		for _, name := range []string{".bash_profile", ".bash_login"} {
			_, err := os.Stat(filepath.Join(home, name))
			if err == nil {
				login = filepath.Join(home, name)
				break
			}
			if !errors.Is(err, os.ErrNotExist) {
				return err
			}
		}
		files = []string{login, filepath.Join(home, ".bashrc")}
	case "fish":
		if configDir == "" {
			configDir = filepath.Join(home, ".config")
		}
		q = "'" + strings.NewReplacer("\\", "\\\\", "'", "\\'").Replace(dir) + "'"
		body = "if test \"$PATH[1]\" != " + q + "\n  set -gx PATH " + q + " $PATH\nend\n"
		files = []string{filepath.Join(configDir, "fish", "conf.d", "secrethandoff.fish")}
	case "sh", "dash", ".":
		files = []string{filepath.Join(home, ".profile")}
	default:
		return fmt.Errorf("unsupported shell %q: add %s to PATH, then rerun with a supported SHELL (sh, bash, zsh, fish)", shell, dir)
	}
	for _, path := range files {
		if err := updatePathFile(path, body, dry); err != nil {
			return err
		}
		if dry {
			fmt.Fprintf(out, "would update PATH: %s\n", path)
		} else {
			fmt.Fprintf(out, "ok   PATH: %s\n", path)
		}
	}
	return nil
}

func updatePathFile(path, body string, dry bool) error {
	// Follow dotfile symlinks without replacing the symlink itself.
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return err
		}
		path = resolved
	}
	data, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	text := string(data)
	block := pathStart + "\n" + body + pathEnd + "\n"
	start, end := strings.Index(text, pathStart), strings.Index(text, pathEnd)
	if start >= 0 && end > start && strings.Count(text, pathStart) == 1 && strings.Count(text, pathEnd) == 1 {
		text = text[:start] + block + strings.TrimPrefix(text[end+len(pathEnd):], "\n")
	} else if start >= 0 || end >= 0 {
		return fmt.Errorf("%s has an incomplete or repeated Secret Handoff PATH block; repair it before rerunning setup", path)
	} else {
		if text != "" && !strings.HasSuffix(text, "\n") {
			text += "\n"
		}
		text += "\n" + block
	}
	if dry || text == string(data) {
		return nil
	}
	mode := os.FileMode(0o644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode().Perm()
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".secrethandoff-path-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := io.WriteString(f, text); err != nil {
		return err
	}
	if err := f.Chmod(mode); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), path)
}
