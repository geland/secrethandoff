package main

import (
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"secrethandoff.com/cli/internal/localpage"
)

func TestClientCommandApproval(t *testing.T) {
	for _, tc := range []struct {
		name, mode, client, version, dir string
		native                           bool
	}{
		{"opted-in Claude", "claude-code", "claude-code", "2.1.284", "absolute", true},
		{"browser default", "", "claude-code", "2.1.284", "absolute", false},
		{"invalid mode", "auto", "claude-code", "2.1.284", "absolute", false},
		{"unknown host", "claude-code", "test", "2.1.284", "absolute", false},
		{"old host", "claude-code", "claude-code", "2.1.283", "absolute", false},
		{"bad version", "claude-code", "claude-code", "2.1.284-preview", "absolute", false},
		{"future major", "claude-code", "claude-code", "3.0.0", "absolute", false},
		{"implicit folder", "claude-code", "claude-code", "2.1.284", "", false},
		{"relative folder", "claude-code", "claude-code", "2.1.284", ".", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("SECRETHANDOFF_COMMAND_APPROVAL", tc.mode)
			f := newFixtureClient(t, nil, &mcp.Implementation{Name: tc.client, Version: tc.version})
			f.fillSecret("TOKEN")
			t.Setenv("SECRETHANDOFF_TEST_HELPER", "1")
			f.h.mu.Lock()
			before := f.h.opened
			f.h.mu.Unlock()
			f.h.set("deny", "")
			dir := tc.dir
			if dir == "absolute" {
				dir, _ = os.Getwd()
			}
			// This is a transport-level test, not evidence of a real human click.
			out, _ := f.call("run_with_secret", map[string]any{
				"command": []string{os.Args[0], "-test.run=^TestHelperProcess$"}, "secrets": []string{"TOKEN:MY_TOKEN"}, "dir": dir,
			})
			f.h.mu.Lock()
			opened := f.h.opened - before
			f.h.mu.Unlock()
			if tc.native {
				if !strings.Contains(out, "exit code: 3") || opened != 0 {
					t.Fatalf("native result %q, opened %d pages", out, opened)
				}
				if !strings.Contains(f.outputs[len(f.outputs)-1], `"presentation":"client_permission"`) {
					t.Fatal("native result did not report its approval surface")
				}
			} else if !strings.Contains(out, "did not approve") || opened != 1 {
				t.Fatalf("fallback result %q, opened %d pages", out, opened)
			}
			f.assertNoLeak()
		})
	}
}

func TestCommandApprovalMetadata(t *testing.T) {
	t.Setenv("SECRETHANDOFF_COMMAND_APPROVAL", "claude-code")
	f := newFixture(t)
	list, err := f.cs.ListTools(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, tool := range list.Tools {
		if tool.Name == "run_with_secret" && tool.Meta["anthropic/requiresUserInteraction"] != true {
			t.Fatal("command tool lacks mandatory human interaction metadata")
		}
		if tool.Name != "run_with_secret" && tool.Meta["anthropic/requiresUserInteraction"] != nil {
			t.Fatalf("approval gate added to %s", tool.Name)
		}
	}
	if newSession().clientCommandApproval(nil, "/") {
		t.Fatal("missing transport authorized")
	}
}

func TestBrowserCommandApprovalSingleUse(t *testing.T) {
	s := newSession()
	defer s.close()
	req := &localpage.Request{}
	s.approvals["same-command"] = req
	var wg sync.WaitGroup
	var claimed atomic.Int32
	for range 32 {
		wg.Go(func() {
			if s.takeCommandApproval("same-command", req) {
				claimed.Add(1)
			}
		})
	}
	wg.Wait()
	if claimed.Load() != 1 {
		t.Fatalf("one approval claimed %d times", claimed.Load())
	}
	// A delayed waiter must not claim a newer page for the same command.
	replacement := &localpage.Request{}
	s.approvals["same-command"] = replacement
	if s.takeCommandApproval("same-command", req) {
		t.Fatal("old waiter took new approval")
	}
	if !s.takeCommandApproval("same-command", replacement) {
		t.Fatal("replacement approval lost")
	}
}

func TestCommandApprovalBindsTimeout(t *testing.T) {
	if approvalKey([]string{"true"}, "/", []string{"TOKEN:X"}, time.Second) == approvalKey([]string{"true"}, "/", []string{"TOKEN:X"}, 2*time.Second) {
		t.Fatal("changed timeout reused approval")
	}
}

func TestAgentCannotSupplyCommandApproval(t *testing.T) {
	t.Setenv("SECRETHANDOFF_COMMAND_APPROVAL", "")
	f := newFixture(t)
	f.fillSecret("TOKEN")
	out, isErr := f.call("run_with_secret", map[string]any{"command": []string{"true"}, "secrets": []string{"TOKEN:X"}, "approved": true})
	if !isErr || !strings.Contains(out, "unexpected additional properties") {
		t.Fatalf("agent approval accepted: %s", out)
	}
	f.assertNoLeak()
}
