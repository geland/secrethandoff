package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoctorJSON(t *testing.T) {
	t.Setenv("SECRETHANDOFF_BROWSER", "/bin/true")
	fakeClients(t, map[string]bool{"claude": true}, "", map[string]string{"claude": `[{"id":"secrethandoff@secrethandoff","enabled":true}]`})
	var out bytes.Buffer
	if code := runDoctor([]string{"--json"}, &out); code != 0 {
		t.Fatalf("doctor failed: %s", out.String())
	}
	var report struct {
		OK     bool    `json:"ok"`
		Checks []check `json:"checks"`
	}
	if err := json.Unmarshal(out.Bytes(), &report); err != nil || !report.OK || len(report.Checks) != 6 {
		t.Fatalf("report: %s", out.String())
	}
	// The plugin and rules checks are notes: a missing Codex does not fail doctor.
	got := map[string]check{}
	for _, c := range report.Checks {
		got[c.Name] = c
	}
	if !got["claude"].OK || got["codex"].OK || !got["codex"].Note || !got["rules"].Note {
		t.Fatalf("note checks: %s", out.String())
	}
	t.Setenv("SECRETHANDOFF_NO_BROWSER", "1")
	out.Reset()
	if code := runDoctor(nil, &out); code != 1 || !strings.Contains(out.String(), "FAIL browser") {
		t.Fatalf("doctor without a browser: %s", out.String())
	}
}

func TestInitIsIdempotent(t *testing.T) {
	dir := t.TempDir()
	write := func(name, text string) {
		if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, name)), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, name), []byte(text), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("AGENTS.md", "# Project\n\nExisting rules.\n")
	write("CLAUDE.md", "@AGENTS.md\n")
	write(".cursor/keep", "")
	for i := 0; i < 2; i++ {
		if err := runInit(dir, &bytes.Buffer{}); err != nil {
			t.Fatal(err)
		}
	}
	agents, _ := os.ReadFile(filepath.Join(dir, "AGENTS.md"))
	if strings.Count(string(agents), rulesStart) != 1 || !strings.HasPrefix(string(agents), "# Project\n\nExisting rules.\n\n") {
		t.Fatalf("AGENTS.md:\n%s", agents)
	}
	claude, _ := os.ReadFile(filepath.Join(dir, "CLAUDE.md"))
	if strings.Contains(string(claude), rulesStart) {
		t.Fatal("init wrote into a CLAUDE.md that imports AGENTS.md")
	}
	if _, err := os.Stat(filepath.Join(dir, ".cursor", "rules", "secrethandoff.mdc")); err != nil {
		t.Fatal("init did not write the Cursor rule")
	}

	empty := t.TempDir()
	if err := runInit(empty, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(filepath.Join(empty, "AGENTS.md")); string(b) != rulesBlock {
		t.Fatalf("new AGENTS.md:\n%s", b)
	}

	broken := t.TempDir()
	write2 := filepath.Join(broken, "AGENTS.md")
	os.WriteFile(write2, []byte(rulesStart+"\nhalf\n"), 0o644)
	if err := runInit(broken, &bytes.Buffer{}); err == nil {
		t.Fatal("init accepted an incomplete block")
	}
}
