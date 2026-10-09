package main

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func testSetupSystem(t *testing.T) setupSystem {
	t.Helper()
	root := t.TempDir()
	source := filepath.Join(root, "download")
	if err := os.WriteFile(source, []byte("test executable\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(root, "project")
	if err := os.Mkdir(project, 0o755); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "home")
	return setupSystem{source: source, binDir: filepath.Join(root, "bin"), project: project,
		savePath: func(dir string, dry bool, out io.Writer) error {
			return persistShellPath(home, "bash", "", "", dir, dry, out)
		},
		doctor: func(io.Writer) int { return 0 },
	}
}

func installedTestBinary(s setupSystem) string {
	name := "secrethandoff"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	return filepath.Join(s.binDir, name)
}

func TestSetupWholeFlowIsRepeatable(t *testing.T) {
	s := testSetupSystem(t)
	calls := fakeClients(t, map[string]bool{"claude": true, "codex": true}, "", nil)
	oldPath := os.Getenv("PATH")
	checks := 0
	s.doctor = func(io.Writer) int {
		checks++
		if !strings.HasPrefix(os.Getenv("PATH"), s.binDir+string(os.PathListSeparator)) {
			t.Fatal("child process PATH missing install")
		}
		return 0
	}
	for i := 0; i < 2; i++ {
		var out, errOut bytes.Buffer
		if code := executeSetup(setupOptions{marketplace: "owner/repo", init: true}, s, strings.NewReader(""), &out, &errOut); code != 0 {
			t.Fatalf("setup %d: %s %s", code, &out, &errOut)
		}
		if !strings.Contains(out.String(), "Setup verified") {
			t.Fatal(out.String())
		}
	}
	if checks != 2 || len(*calls) != 4 {
		t.Fatalf("checks=%d client mutations=%v", checks, *calls)
	}
	if os.Getenv("PATH") != oldPath {
		t.Fatal("setup leaked PATH into its caller")
	}
	b, err := os.ReadFile(installedTestBinary(s))
	if err != nil || string(b) != "test executable\n" {
		t.Fatalf("installed binary: %s %v", b, err)
	}
	rules, _ := os.ReadFile(filepath.Join(s.project, "AGENTS.md"))
	if strings.Count(string(rules), rulesStart) != 1 {
		t.Fatalf("rules repeated: %s", rules)
	}
}

func TestSetupDryRunHasNoSideEffects(t *testing.T) {
	s := testSetupSystem(t)
	calls := fakeClients(t, map[string]bool{"claude": true}, "", nil)
	s.doctor = func(io.Writer) int { t.Fatal("doctor ran in dry-run"); return 1 }
	var out bytes.Buffer
	if code := executeSetup(setupOptions{marketplace: "owner/repo", dryRun: true, init: true}, s, strings.NewReader(""), &out, &bytes.Buffer{}); code != 0 {
		t.Fatal(code)
	}
	for _, path := range []string{s.binDir, filepath.Join(filepath.Dir(s.source), "home"), filepath.Join(s.project, "AGENTS.md")} {
		if _, err := os.Stat(path); !os.IsNotExist(err) {
			t.Fatalf("dry-run wrote %s: %v", path, err)
		}
	}
	if len(*calls) != 0 || !strings.Contains(out.String(), "would verify") {
		t.Fatalf("dry-run: %s %v", &out, *calls)
	}
}

func TestSetupInitRequiresConsent(t *testing.T) {
	for _, tc := range []struct {
		name, input               string
		interactive, noInit, want bool
	}{
		{"yes", "yes\n", true, false, true}, {"no", "n\n", true, false, false}, {"eof", "", true, false, false},
		{"noninteractive", "yes\n", false, false, false}, {"no-init", "yes\n", true, true, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testSetupSystem(t)
			s.interactive = tc.interactive
			fakeClients(t, map[string]bool{"claude": true}, "", nil)
			if code := executeSetup(setupOptions{marketplace: "owner/repo", noInit: tc.noInit}, s, strings.NewReader(tc.input), &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
				t.Fatal(code)
			}
			ok, _ := projectHasRules(s.project)
			if ok != tc.want {
				t.Fatalf("project guidance=%v, want %v", ok, tc.want)
			}
		})
	}
}

func TestSetupReportsIncompleteInstallation(t *testing.T) {
	for _, tc := range []struct {
		name    string
		clients map[string]bool
		list    map[string]string
		doctor  int
	}{
		{"no-clients", map[string]bool{}, nil, 0},
		{"plugin-disabled", map[string]bool{"claude": true}, map[string]string{"claude": `[{"id":"secrethandoff@secrethandoff","enabled":false}]`}, 0},
		{"host-check-failed", map[string]bool{"claude": true}, nil, 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := testSetupSystem(t)
			s.doctor = func(io.Writer) int { return tc.doctor }
			fakeClients(t, tc.clients, "", tc.list)
			var out, errOut bytes.Buffer
			if code := executeSetup(setupOptions{marketplace: "owner/repo"}, s, strings.NewReader(""), &out, &errOut); code != 1 {
				t.Fatalf("code %d: %s %s", code, &out, &errOut)
			}
			if strings.Contains(out.String(), "Setup verified") {
				t.Fatal("reported success")
			}
		})
	}
}

func TestBinaryOnlySkipsClientsAndProject(t *testing.T) {
	s := testSetupSystem(t)
	s.doctor = func(io.Writer) int { t.Fatal("doctor ran for binary-only"); return 1 }
	calls := fakeClients(t, map[string]bool{"claude": true}, "", nil)
	if code := executeSetup(setupOptions{binaryOnly: true}, s, strings.NewReader("yes\n"), &bytes.Buffer{}, &bytes.Buffer{}); code != 0 {
		t.Fatal(code)
	}
	if len(*calls) != 0 {
		t.Fatal(*calls)
	}
	if _, err := os.Stat(installedTestBinary(s)); err != nil {
		t.Fatal(err)
	}
	if ok, _ := projectHasRules(s.project); ok {
		t.Fatal("binary-only wrote rules")
	}
}

func TestSetupRejectsConflictingFlags(t *testing.T) {
	for _, args := range [][]string{{"--init", "--no-init"}, {"--init", "--binary-only"}, {"--unknown"}, {"--marketplace"}, {"extra"}} {
		if _, err := parseSetup(args, &bytes.Buffer{}); err == nil {
			t.Fatalf("accepted %v", args)
		}
	}
}

func TestExecutableInstallPreservesExistingOnFailure(t *testing.T) {
	dir := t.TempDir()
	source := filepath.Join(dir, "download")
	dest := filepath.Join(dir, "bin", "secrethandoff")
	os.WriteFile(source, []byte("v1"), 0o755)
	if err := installExecutable(source, dest); err != nil {
		t.Fatal(err)
	}
	if err := installExecutable(dest, dest); err != nil {
		t.Fatal(err)
	}
	if err := installExecutable(source+"-missing", dest); err == nil {
		t.Fatal("accepted missing source")
	}
	b, _ := os.ReadFile(dest)
	if string(b) != "v1" {
		t.Fatal("destroyed prior binary")
	}
	os.WriteFile(source, []byte("v2"), 0o755)
	if err := installExecutable(source, dest); err != nil {
		t.Fatal(err)
	}
	b, _ = os.ReadFile(dest)
	if string(b) != "v2" {
		t.Fatal("did not update binary")
	}
	files, _ := filepath.Glob(filepath.Join(filepath.Dir(dest), ".secrethandoff-install-*"))
	if len(files) != 0 {
		t.Fatal(files)
	}
	link := filepath.Join(dir, "linked")
	if err := os.Symlink(dest, link); err == nil {
		if err := installExecutable(source, link); err == nil {
			t.Fatal("replaced symlink destination")
		}
	}
}

func TestPathEditsPreserveUserContentAndAreIdempotent(t *testing.T) {
	for _, shell := range []string{"bash", "zsh", "fish", "sh"} {
		t.Run(shell, func(t *testing.T) {
			home := t.TempDir()
			bin := filepath.Join(home, "a space's bin")
			profile := filepath.Join(home, ".profile")
			os.WriteFile(profile, []byte("# existing\nexport EXAMPLE=kept\n"), 0o600)
			for i := 0; i < 2; i++ {
				if err := persistShellPath(home, shell, "", "", bin, false, &bytes.Buffer{}); err != nil {
					t.Fatal(err)
				}
			}
			filepath.WalkDir(home, func(path string, entry os.DirEntry, err error) error {
				if err != nil {
					t.Fatal(err)
				}
				if entry.IsDir() {
					return nil
				}
				b, _ := os.ReadFile(path)
				if strings.Count(string(b), pathStart) > 1 {
					t.Fatalf("duplicate PATH block %s", path)
				}
				return nil
			})
			b, _ := os.ReadFile(profile)
			if !strings.HasPrefix(string(b), "# existing\nexport EXAMPLE=kept\n") {
				t.Fatal("lost user content")
			}
		})
	}
	home := t.TempDir()
	profile := filepath.Join(home, ".profile")
	broken := pathStart + "\nbroken\n"
	os.WriteFile(profile, []byte(broken), 0o644)
	if err := persistShellPath(home, "sh", "", "", filepath.Join(home, "bin"), false, &bytes.Buffer{}); err == nil {
		t.Fatal("accepted incomplete PATH block")
	}
	b, _ := os.ReadFile(profile)
	if string(b) != broken {
		t.Fatal("rewrote broken profile")
	}
}

func TestMarketplaceRecoveryChecksSource(t *testing.T) {
	for _, tc := range []struct {
		data, source string
		want         bool
	}{
		{`[{"name":"secrethandoff","source":"directory","path":"/local/plugin"}]`, "/local/plugin", true},
		{`[{"name":"secrethandoff","source":"github","repo":"owner/repo"}]`, "owner/repo", true},
		{`{"marketplaces":[{"name":"secrethandoff","marketplaceSource":{"source":"owner/repo"}}]}`, "owner/repo", true},
		{`[{"name":"secrethandoff","repo":"unexpected/repo"}]`, "owner/repo", false},
		{`[{"name":"different","repo":"owner/repo"}]`, "owner/repo", false},
		{`not json`, "owner/repo", false},
	} {
		if got := marketplaceMatches([]byte(tc.data), tc.source); got != tc.want {
			t.Fatalf("%s => %v", tc.data, got)
		}
	}
}
