package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestGroupedRawTransportLeak(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "secrethandoff")
	browser := filepath.Join(dir, "group-browser")
	if os.PathSeparator == '\\' {
		bin += ".exe"
		browser += ".exe"
	}
	for _, args := range [][]string{{"build", "-o", bin, "."}, {"build", "-o", browser, "./testdata/group-browser"}} {
		if _, err := exec.Command("go", args...).CombinedOutput(); err != nil {
			t.Fatal("could not build grouped leak fixtures")
		}
	}
	values, _ := json.Marshal(groupValues)
	cmd := exec.Command(bin, "mcp")
	cmd.Env = append(os.Environ(), "SECRETHANDOFF_BROWSER="+browser, "SECRETHANDOFF_GROUP_DUMMY_VALUES="+string(values), "SECRETHANDOFF_WAIT_SECONDS=10", "SECRETHANDOFF_COMMAND_APPROVAL=browser", "SECRETHANDOFF_GROUP_HELPER=1")
	stderr, stdout := &lockedBuffer{}, &lockedBuffer{}
	cmd.Stderr = stderr
	stdin, _ := cmd.StdinPipe()
	pipe, _ := cmd.StdoutPipe()
	if cmd.Start() != nil {
		t.Fatal("could not start grouped binary")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "group-leak-test", Version: "1"}, nil).Connect(ctx, &mcp.IOTransport{Reader: teeReadCloser{io.TeeReader(pipe, stdout), pipe}, Writer: stdin}, nil)
	if err != nil {
		t.Fatal("could not connect grouped binary")
	}
	defer func() { cs.Close(); stdin.Close(); cmd.Wait() }()
	call := func(name string, args map[string]any) *mcp.CallToolResult {
		r, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatal("grouped binary call failed")
		}
		b, _ := json.Marshal(r)
		assertGroupClean(t, string(b))
		return r
	}
	r := call("request_secrets", groupArgs)
	if r.IsError || r.StructuredContent.(map[string]any)["status"] != "ready" {
		t.Fatal("binary group did not become ready")
	}
	call("wait_for_secret", map[string]any{"name": "LOGIN"})
	call("list_secrets", nil)
	call("http_request", map[string]any{"method": "GET", "url": "https://other.invalid/?u={{secret:LOGIN_USER}}&p={{secret:LOGIN_PASS}}"})
	cwd, _ := os.Getwd()
	self, _ := os.Executable()
	r = call("run_with_secret", map[string]any{"command": []string{self, "-test.run=^TestGroupedCommandProcess$"}, "dir": cwd, "secrets": []string{"LOGIN_USER:GROUP_USER", "LOGIN_PASS:GROUP_PASS"}})
	b, _ := json.Marshal(r)
	if !strings.Contains(string(b), "[REDACTED:LOGIN_USER]") || !strings.Contains(string(b), "[REDACTED:LOGIN_PASS]") {
		t.Fatal("binary command did not exercise both redactions")
	}
	call("run_with_secret", map[string]any{"command": []string{"definitely-missing-group-command"}, "dir": cwd, "secrets": []string{"LOGIN_USER:GROUP_USER", "LOGIN_PASS:GROUP_PASS"}})
	call("forget_secret", map[string]any{"name": "LOGIN"})
	call("list_secrets", nil)
	call("wait_for_secret", map[string]any{"name": "LOGIN"})
	cs.Close()
	stdin.Close()
	cmd.Wait()
	assertGroupClean(t, stdout.String(), stderr.String())
	if regexp.MustCompile(`/r#[A-Za-z0-9_-]{43}`).MatchString(stdout.String() + stderr.String()) {
		t.Fatal("group page token escaped transport")
	}
}
