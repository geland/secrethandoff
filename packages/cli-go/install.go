package main

import (
	"bufio"
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"unicode"

	"golang.org/x/term"
)

type setupOptions struct {
	marketplace, binDir              string
	dryRun, init, noInit, binaryOnly bool
}

// setupSystem keeps filesystem and host checks explicit. Tests use a temporary
// home and executable; they never install the test runner into the user's PATH.
type setupSystem struct {
	source, binDir, project string
	interactive             bool
	savePath                func(string, bool, io.Writer) error
	doctor                  func(io.Writer) int
}

func runSetupWithInput(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	o, err := parseSetup(args, stderr)
	if err != nil {
		if errors.Is(err, flag.ErrHelp) {
			return 0
		}
		return 2
	}
	source, err := os.Executable()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	project, err := os.Getwd()
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 1
	}
	binDir := os.Getenv("SECRETHANDOFF_BIN_DIR")
	if binDir == "" {
		binDir = filepath.Join(home, ".local", "bin")
		if runtime.GOOS == "windows" {
			base := os.Getenv("LOCALAPPDATA")
			if base == "" {
				base = filepath.Join(home, "AppData", "Local")
			}
			binDir = filepath.Join(base, "Programs", "secrethandoff")
		}
	}
	interactive := false
	if f, ok := stdin.(*os.File); ok {
		interactive = term.IsTerminal(int(f.Fd()))
	}
	s := setupSystem{source: source, binDir: binDir, project: project, interactive: interactive,
		savePath: func(dir string, dry bool, out io.Writer) error { return persistUserPath(home, dir, dry, out) },
		doctor:   func(out io.Writer) int { return runDoctor(nil, out) },
	}
	return executeSetup(o, s, stdin, stdout, stderr)
}

func parseSetup(args []string, stderr io.Writer) (setupOptions, error) {
	o := setupOptions{}
	f := flag.NewFlagSet("secrethandoff setup", flag.ContinueOnError)
	f.SetOutput(stderr)
	f.StringVar(&o.marketplace, "marketplace", defaultMarketplace, "plugin marketplace repository or local directory")
	f.StringVar(&o.binDir, "bin-dir", "", "install directory (default: user binary directory)")
	f.BoolVar(&o.dryRun, "dry-run", false, "show planned changes without modifying anything")
	f.BoolVar(&o.init, "init", false, "add agent guidance to the current project")
	f.BoolVar(&o.noInit, "no-init", false, "skip the project guidance prompt")
	f.BoolVar(&o.binaryOnly, "binary-only", false, "install the binary and PATH only")
	err := f.Parse(args)
	if err == nil && (f.NArg() != 0 || o.marketplace == "" || strings.HasPrefix(o.marketplace, "-") || (o.init && (o.noInit || o.binaryOnly))) {
		err = errors.New("invalid setup arguments: --init cannot be combined with --no-init or --binary-only")
		fmt.Fprintln(stderr, err)
	}
	return o, err
}

func executeSetup(o setupOptions, s setupSystem, stdin io.Reader, stdout, stderr io.Writer) int {
	fail := func(err error) int { fmt.Fprintln(stderr, "secrethandoff setup:", err); return 1 }
	dir := s.binDir
	if o.binDir != "" {
		dir = o.binDir
	}
	dir, err := filepath.Abs(dir)
	if err != nil {
		return fail(err)
	}
	if strings.ContainsRune(dir, os.PathListSeparator) {
		return fail(errors.New("install directory cannot contain a PATH separator"))
	}
	if strings.IndexFunc(dir, unicode.IsControl) >= 0 {
		return fail(errors.New("install directory contains control characters"))
	}
	name := "secrethandoff"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	dest := filepath.Join(dir, name)
	if o.dryRun {
		fmt.Fprintf(stdout, "would install: %s\n", dest)
	} else {
		if err := installExecutable(s.source, dest); err != nil {
			return fail(err)
		}
		fmt.Fprintf(stdout, "ok   binary: %s\n", dest)
	}
	if err := s.savePath(dir, o.dryRun, stdout); err != nil {
		return fail(err)
	}
	if !o.dryRun {
		// Child client CLIs see the new binary now. Parent shells and already
		// running applications need a restart to inherit their updated PATH.
		oldPath, hadPath := os.LookupEnv("PATH")
		if err := os.Setenv("PATH", dir+string(os.PathListSeparator)+oldPath); err != nil {
			return fail(err)
		}
		defer func() {
			if hadPath {
				_ = os.Setenv("PATH", oldPath)
			} else {
				_ = os.Unsetenv("PATH")
			}
		}()
	}
	if o.binaryOnly {
		fmt.Fprintln(stdout, "Binary installation only. Open a new terminal before using secrethandoff.")
		return 0
	}
	clientCode := setupClients(o.marketplace, o.dryRun, stdout, stderr)
	initProject := o.init
	if !o.dryRun && !o.init && !o.noInit && s.interactive {
		if present, _ := projectHasRules(s.project); !present {
			fmt.Fprintf(stdout, "Add secret-handling guidance to agent rule files in %s? [y/N] ", s.project)
			line, _ := bufio.NewReader(stdin).ReadString('\n')
			answer := strings.ToLower(strings.TrimSpace(line))
			initProject = answer == "y" || answer == "yes"
		}
	}
	if initProject {
		if o.dryRun {
			fmt.Fprintf(stdout, "would add project guidance: %s\n", s.project)
		} else if err := runInit(s.project, stdout); err != nil {
			return fail(err)
		}
	} else {
		fmt.Fprintln(stdout, "Optional project guidance: run secrethandoff init in your project.")
	}
	if o.dryRun {
		fmt.Fprintln(stdout, "would verify: binary, browser, loopback, plugins, project guidance")
		return 0
	}
	if s.doctor(stdout) != 0 || clientCode != 0 {
		fmt.Fprintln(stderr, "Setup needs attention. Fix the reported checks, then rerun secrethandoff setup.")
		return 1
	}
	fmt.Fprintln(stdout, "Setup verified. Open a new terminal and start a new agent session.")
	return 0
}

// Copy through a sibling temporary file: an interrupted copy must not destroy
// the previous binary. Symlink destinations belong to another installation.
func installExecutable(source, dest string) error {
	src, err := os.Open(source)
	if err != nil {
		return err
	}
	defer src.Close()
	srcInfo, err := src.Stat()
	if err != nil {
		return err
	}
	if !srcInfo.Mode().IsRegular() {
		return errors.New("source executable is not a regular file")
	}
	if dstInfo, err := os.Lstat(dest); err == nil {
		if !dstInfo.Mode().IsRegular() {
			return fmt.Errorf("refusing to replace non-regular install destination %s", dest)
		}
		if os.SameFile(srcInfo, dstInfo) {
			return nil
		}
		// Avoid replacing identical bytes, including a running Windows binary.
		a, readErr := os.ReadFile(source)
		b, dstErr := os.ReadFile(dest)
		if readErr == nil && dstErr == nil && bytes.Equal(a, b) {
			return os.Chmod(dest, 0o755)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(dest), 0o755); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(dest), ".secrethandoff-install-*")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if _, err := io.Copy(f, src); err != nil {
		return err
	}
	if err := f.Chmod(0o755); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Rename(f.Name(), dest)
}
