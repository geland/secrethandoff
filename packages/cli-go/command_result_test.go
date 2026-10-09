package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// Only dummy values enter this child. Its output exercises both MCP result
// representations, including encodings and JSON/HTML-sensitive characters.
func TestCommandResultProcess(t *testing.T) {
	mode := os.Getenv("SECRETHANDOFF_RESULT_HELPER")
	if mode == "" {
		return
	}
	v := os.Getenv("MY_TOKEN")
	if readyURL := os.Getenv("SECRETHANDOFF_RESULT_READY_URL"); readyURL != "" {
		res, err := http.Get(readyURL)
		if err != nil {
			os.Exit(9)
		}
		res.Body.Close()
	}
	fmt.Printf("checked=%t raw=%s encoded=%s\n", v != "", v, base64.StdEncoding.EncodeToString([]byte(v)))
	fmt.Fprintf(os.Stderr, "stderr=%s\n", v)
	switch mode {
	case "nonzero":
		os.Exit(7)
	case "timeout":
		time.Sleep(10 * time.Second)
	case "truncated":
		fmt.Print(strings.Repeat("x", maxCommandOutput+1))
		fmt.Fprint(os.Stderr, strings.Repeat("y", maxCommandOutput+1))
	}
	os.Exit(0)
}

func (f *fixture) commandCall(args map[string]any, status string, isError bool) map[string]any {
	f.t.Helper()
	res, err := f.cs.CallTool(f.ctx, &mcp.CallToolParams{Name: "run_with_secret", Arguments: args})
	if err != nil {
		f.t.Fatal(err)
	}
	b, err := json.Marshal(res)
	if err != nil {
		f.t.Fatal(err)
	}
	f.outputs = append(f.outputs, string(b))
	data, ok := res.StructuredContent.(map[string]any)
	if !ok || data["status"] != status || res.IsError != isError {
		f.t.Fatalf("expected %s, isError=%t, got %s", status, isError, b)
	}
	return data
}

func TestCommandResultsAreCompleteWithoutText(t *testing.T) {
	for _, surface := range []string{"browser_page", "client_permission"} {
		for _, mode := range []string{"success", "nonzero", "timeout", "truncated", "missing_program"} {
			t.Run(surface+"/"+mode, func(t *testing.T) {
				t.Setenv("SECRETHANDOFF_COMMAND_APPROVAL", "")
				if surface == "client_permission" {
					t.Setenv("SECRETHANDOFF_COMMAND_APPROVAL", "claude-code")
				}
				f := newFixtureClient(t, nil, &mcp.Implementation{Name: "claude-code", Version: "2.1.284"})
				f.fillSecret("TOKEN")
				f.h.set("approve", "")
				t.Setenv("SECRETHANDOFF_RESULT_HELPER", mode)
				dir, _ := os.Getwd()
				command := []string{os.Args[0], "-test.run=^TestCommandResultProcess$"}
				status, wantError := "command_finished", mode == "nonzero" || mode == "timeout"
				if mode == "missing_program" {
					command = []string{filepath.Join(t.TempDir(), "absent-program")}
					status, wantError = "command_not_started", true
				}
				timeout := 5
				if mode == "timeout" {
					timeout = 1
				}
				args := map[string]any{"command": command, "secrets": []string{"TOKEN:MY_TOKEN"}, "dir": dir, "timeout_seconds": timeout}
				data := f.commandCall(args, status, wantError)
				if data["approval"] != "approved" || data["presentation"] != surface {
					t.Fatalf("approval metadata: %v", data)
				}
				if mode == "missing_program" {
					if data["executed"] != false || data["exit_code"] != nil || data["stdout"] != nil || data["message"] == nil {
						t.Fatalf("startup failure claimed execution: %v", data)
					}
				} else {
					code := float64(0)
					if mode == "nonzero" {
						code = 7
					}
					if mode == "timeout" {
						code = -1
					}
					if data["executed"] != true || data["exit_code"] != code || data["timed_out"] != (mode == "timeout") || data["cancelled"] != false {
						t.Fatalf("execution outcome: %v", data)
					}
					for _, stream := range []string{"stdout", "stderr"} {
						output, ok := data[stream].(string)
						if !ok || !strings.Contains(output, "[REDACTED:TOKEN]") || data[stream+"_truncated"] != (mode == "truncated") {
							t.Fatalf("incomplete %s", stream)
						}
					}
				}
				f.assertNoLeak()
			})
		}
	}
}

func TestCommandApprovalOutcomesDoNotClaimExecution(t *testing.T) {
	for _, action := range []string{"deny", "ignore"} {
		t.Run(action, func(t *testing.T) {
			t.Setenv("SECRETHANDOFF_COMMAND_APPROVAL", "")
			f := newFixture(t)
			f.fillSecret("TOKEN")
			f.h.set(action, "")
			if action == "ignore" {
				f.s.wait = 5 * time.Millisecond
			}
			approval := "denied"
			if action == "ignore" {
				approval = "pending"
			}
			data := f.commandCall(map[string]any{"command": []string{"true"}, "secrets": []string{"TOKEN:X"}}, "command_"+approval, false)
			if data["executed"] != false || data["approval"] != approval || data["exit_code"] != nil || data["presentation"] != "browser_page" {
				t.Fatalf("unexecuted result: %v", data)
			}
			f.assertNoLeak()
		})
	}
}

func TestCommandOutputRedactionSurvivesForget(t *testing.T) {
	f := newFixture(t)
	dummy := "dummy-<>&\"\\\n-token-12345678"
	f.h.set("fill", dummy)
	f.lifecycleCall("request_secret", map[string]any{"name": "TOKEN", "reason": "Test", "policy": stripePolicy}, "ready")
	ready, resume := make(chan struct{}), make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		close(ready)
		<-resume
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	t.Setenv("SECRETHANDOFF_RESULT_HELPER", "success")
	t.Setenv("SECRETHANDOFF_RESULT_READY_URL", server.URL)
	done := make(chan *mcp.CallToolResult, 1)
	go func() {
		done <- f.s.execute(f.ctx, []string{os.Args[0], "-test.run=^TestCommandResultProcess$"}, "", []envBinding{{name: "TOKEN", env: "MY_TOKEN"}}, 5*time.Second, "browser_page")
	}()
	select {
	case <-ready:
	case <-time.After(5 * time.Second):
		close(resume)
		t.Fatal("child did not start")
	}
	f.s.store.Forget("TOKEN")
	close(resume)
	res := <-done
	b, err := metadataJSON(res)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range []string{dummy, base64.StdEncoding.EncodeToString([]byte(dummy))} {
		if strings.Contains(string(b), value) {
			t.Fatal("forgotten secret escaped in output")
		}
	}
	data := res.StructuredContent.(map[string]any)
	for _, stream := range []string{"stdout", "stderr"} {
		if !strings.Contains(data[stream].(string), "[REDACTED:TOKEN]") {
			t.Fatalf("%s lost redaction", stream)
		}
	}
	if data["executed"] != true || data["exit_code"] != float64(0) {
		t.Fatal("child did not complete")
	}
	for _, block := range res.Content {
		if text, ok := block.(*mcp.TextContent); ok && !strings.Contains(text.Text, "[REDACTED:TOKEN]") {
			t.Fatal("compatibility text lost redaction")
		}
	}
}

func TestCommandCancelledBeforeStart(t *testing.T) {
	f := newFixture(t)
	f.fillSecret("TOKEN")
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	res := f.s.execute(ctx, []string{"true"}, "", []envBinding{{name: "TOKEN", env: "X"}}, time.Second, "browser_page")
	data := res.StructuredContent.(map[string]any)
	if data["executed"] != false || data["status"] != "command_not_started" || data["cancelled"] != true {
		t.Fatal("cancelled call claimed execution")
	}
}
