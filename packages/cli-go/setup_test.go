package main

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fakeClients replaces the agent CLI seams. present names the commands on
// PATH; each call is recorded as "command arg arg".
func fakeClients(t *testing.T, present map[string]bool, fail string, list map[string]string) *[]string {
	t.Helper()
	calls := &[]string{}
	installed := map[string]bool{}
	oldLook, oldRun := lookPath, runClient
	t.Cleanup(func() { lookPath, runClient = oldLook, oldRun })
	lookPath = func(name string) (string, error) {
		if present[name] {
			return "/fake/" + name, nil
		}
		return "", errors.New("not found")
	}
	runClient = func(_ context.Context, path string, args ...string) ([]byte, error) {
		call := filepath.Base(path) + " " + strings.Join(args, " ")
		if strings.Join(args, " ") == "plugin list --json" {
			if out, ok := list[filepath.Base(path)]; ok {
				return []byte(out), nil
			}
			if installed[filepath.Base(path)] {
				return []byte(`[{"id":"secrethandoff@secrethandoff","enabled":true}]`), nil
			}
			return []byte(`[]`), nil
		}
		*calls = append(*calls, call)
		if fail != "" && strings.Contains(call, fail) {
			return []byte("boom\n"), errors.New("exit status 1")
		}
		if out, ok := list[filepath.Base(path)]; ok && strings.Contains(call, "list --json") {
			return []byte(out), nil
		}
		if strings.Join(args, " ") == "plugin install "+pluginID || strings.Join(args, " ") == "plugin add "+pluginID {
			installed[filepath.Base(path)] = true
		}
		return nil, nil
	}
	return calls
}

func TestSetupInstallsInEachClientOnPath(t *testing.T) {
	calls := fakeClients(t, map[string]bool{"claude": true, "codex": true}, "", nil)
	var out, errOut bytes.Buffer
	if code := setupClients("owner/repo", false, &out, &errOut); code != 0 {
		t.Fatalf("setup failed: %s %s", out.String(), errOut.String())
	}
	want := []string{
		"claude plugin marketplace add owner/repo",
		"claude plugin install secrethandoff@secrethandoff",
		"codex plugin marketplace add owner/repo",
		"codex plugin add secrethandoff@secrethandoff",
	}
	if strings.Join(*calls, "\n") != strings.Join(want, "\n") {
		t.Fatalf("calls:\n%s", strings.Join(*calls, "\n"))
	}

}

func TestSetupSkipsMissingClientsAndUsesAbsoluteLocalPath(t *testing.T) {
	calls := fakeClients(t, map[string]bool{"codex": true}, "", nil)
	dir := t.TempDir()
	wd, _ := os.Getwd()
	t.Cleanup(func() { os.Chdir(wd) }) //nolint:errcheck
	if err := os.Chdir(filepath.Dir(dir)); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if code := setupClients(filepath.Base(dir), false, &out, &bytes.Buffer{}); code != 0 {
		t.Fatalf("setup failed: %s", out.String())
	}
	if !strings.Contains(out.String(), "skip Claude Code") {
		t.Fatalf("no skip line: %s", out.String())
	}
	abs, _ := filepath.EvalSymlinks(dir)
	if len(*calls) != 2 || !(strings.HasSuffix((*calls)[0], dir) || strings.HasSuffix((*calls)[0], abs)) {
		t.Fatalf("calls: %v", *calls)
	}
}

func TestSetupReportsAFailedStep(t *testing.T) {
	calls := fakeClients(t, map[string]bool{"claude": true, "codex": true}, "claude plugin install", nil)
	var errOut bytes.Buffer
	if code := setupClients(defaultMarketplace, false, &bytes.Buffer{}, &errOut); code != 1 {
		t.Fatal("setup did not fail")
	}
	// Claude reports its failed install; Codex still runs.
	if len(*calls) != 4 || !strings.Contains(errOut.String(), "boom") {
		t.Fatalf("calls %v, stderr %s", *calls, errOut.String())
	}
}

func TestSetupDryRunRunsNothing(t *testing.T) {
	calls := fakeClients(t, map[string]bool{"claude": true}, "", nil)
	var out bytes.Buffer
	if code := setupClients(defaultMarketplace, true, &out, &bytes.Buffer{}); code != 0 || len(*calls) != 0 {
		t.Fatalf("code %d, calls %v", code, *calls)
	}
	if !strings.Contains(out.String(), "would run: claude plugin marketplace add "+defaultMarketplace) {
		t.Fatalf("dry run: %s", out.String())
	}
}

func TestListsPluginReadsBothFormats(t *testing.T) {
	cases := map[string]bool{
		`[{"id":"secrethandoff@secrethandoff","enabled":true}]`:                     true,
		`[{"id":"secrethandoff@secrethandoff","enabled":false}]`:                    false,
		`[{"id":"other@x","enabled":true}]`:                                         false,
		`{"installed":[{"pluginId":"secrethandoff@secrethandoff","enabled":true}]}`: true,
		`{"installed":[],"available":[{"pluginId":"secrethandoff@secrethandoff"}]}`: false,
		`not json`: false,
	}
	for in, want := range cases {
		if got := listsPlugin([]byte(in)); got != want {
			t.Errorf("listsPlugin(%s) = %v", in, got)
		}
	}
}

func TestProjectHasRules(t *testing.T) {
	dir := t.TempDir()
	if ok, _ := projectHasRules(dir); ok {
		t.Fatal("empty folder has rules")
	}
	if err := runInit(dir, &bytes.Buffer{}); err != nil {
		t.Fatal(err)
	}
	if ok, detail := projectHasRules(dir); !ok || !strings.Contains(detail, "AGENTS.md") {
		t.Fatalf("after init: %v %s", ok, detail)
	}
}
