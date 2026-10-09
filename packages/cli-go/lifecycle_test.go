package main

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"secrethandoff.com/cli/internal/localpage"
	"secrethandoff.com/cli/internal/policy"
)

func (f *fixture) lifecycleCall(tool string, args map[string]any, status string) map[string]any {
	f.t.Helper()
	res, err := f.cs.CallTool(f.ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
	if err != nil {
		f.t.Fatal(err)
	}
	b, err := json.Marshal(res)
	if err != nil {
		f.t.Fatal(err)
	}
	f.outputs = append(f.outputs, string(b))
	data, ok := res.StructuredContent.(map[string]any)
	if !ok || data["status"] != status {
		f.t.Fatalf("%s: expected %s, got %s", tool, status, b)
	}
	return data
}

func TestLifecycleWaitDoesNotCreateOrChangeRequest(t *testing.T) {
	f := newFixture(t)
	f.h.set("ignore", "")
	f.s.wait = 5 * time.Millisecond
	args := map[string]any{"name": "TOKEN", "reason": "Test", "policy": stripePolicy}
	data := f.lifecycleCall("request_secret", args, "pending")
	if data["presentation"] != "browser_page" || data["next_tool"] != "wait_for_secret" {
		t.Fatalf("pending metadata: %v", data)
	}
	f.lifecycleCall("wait_for_secret", map[string]any{"name": "TOKEN"}, "pending")
	f.h.mu.Lock()
	opened := f.h.opened
	f.h.mu.Unlock()
	if opened != 1 {
		t.Fatalf("wait opened %d pages", opened)
	}
	f.s.mu.Lock()
	req := f.s.fills["TOKEN"].req
	f.s.mu.Unlock()
	if req.Policy.Hosts[0] != "example.com" {
		t.Fatal("wait changed the approved policy")
	}
	if err := req.FillExternal([]byte(testSecret)); err != nil {
		t.Fatal(err)
	}
	f.lifecycleCall("wait_for_secret", map[string]any{"name": "TOKEN"}, "ready")
	f.lifecycleCall("list_secrets", nil, "listed")
	f.lifecycleCall("forget_secret", map[string]any{"name": "TOKEN"}, "forgotten")
	f.lifecycleCall("forget_secret", map[string]any{"name": "TOKEN"}, "missing")
	f.lifecycleCall("wait_for_secret", map[string]any{"name": "TOKEN"}, "missing")
	f.lifecycleCall("wait_for_secret", map[string]any{"name": "NEVER_REQUESTED"}, "missing")
	f.h.mu.Lock()
	defer f.h.mu.Unlock()
	if f.h.opened != 1 {
		t.Fatal("a missing request opened a page")
	}
	f.assertNoLeak()
}

func TestForgetCancelsPendingFillAndWakesWaiter(t *testing.T) {
	f := newFixture(t)
	f.h.set("ignore", "")
	f.s.wait = time.Millisecond
	f.lifecycleCall("request_secret", map[string]any{"name": "TOKEN", "reason": "Test", "policy": stripePolicy}, "pending")
	f.s.mu.Lock()
	fr := f.s.fills["TOKEN"]
	f.s.mu.Unlock()
	f.s.wait = time.Second
	result := make(chan *mcp.CallToolResult, 1)
	go func() { result <- f.s.waitLocal(f.ctx, "TOKEN", fr) }()
	f.lifecycleCall("forget_secret", map[string]any{"name": "TOKEN"}, "forgotten")
	select {
	case res := <-result:
		if res.StructuredContent.(map[string]any)["status"] != "cancelled" {
			t.Fatalf("waiter: %v", res)
		}
	case <-time.After(time.Second):
		t.Fatal("forget did not wake the waiter")
	}
	if err := fr.req.FillExternal([]byte(testSecret)); err == nil {
		t.Fatal("an old page refilled a forgotten secret")
	}
	if f.s.store.Has("TOKEN") {
		t.Fatal("forgotten secret reappeared")
	}
}

func TestLifecycleTerminalStates(t *testing.T) {
	for _, state := range []localpage.State{localpage.Declined, localpage.Rejected, localpage.Expired} {
		t.Run(string(state), func(t *testing.T) {
			f := newFixture(t)
			f.h.set("ignore", "")
			pages, err := f.s.pageServer()
			if err != nil {
				t.Fatal(err)
			}
			p, _ := policy.Parse(policy.Policy{Hosts: []string{"example.com"}})
			ttl := time.Minute
			if state == localpage.Expired {
				ttl = time.Millisecond
			}
			req, err := pages.NewFill("TOKEN", "Test", p, ttl, func([]byte) error { return nil }, nil)
			if err != nil {
				t.Fatal(err)
			}
			if state == localpage.Rejected {
				req.Cancel()
			}
			if state == localpage.Declined {
				// Exercise decline via a real claimed local page.
				f.h.set("decline", "")
				f.s.wait = time.Second
				f.lifecycleCall("request_secret", map[string]any{"name": "DECLINED", "reason": "Test", "policy": stripePolicy}, "declined")
				return
			}
			res := f.s.waitLocal(f.ctx, "TOKEN", &fillRequest{req: req})
			expected := string(state)
			if state == localpage.Rejected {
				expected = "cancelled"
			}
			if res.StructuredContent.(map[string]any)["status"] != expected {
				t.Fatalf("result: %v", res)
			}
		})
	}
}

func TestLifecycleMetadataRedactionSurvivesForget(t *testing.T) {
	f := newFixture(t)
	f.h.set("fill", "example.com") // A human value can coincidentally equal policy metadata.
	f.lifecycleCall("request_secret", map[string]any{"name": "TOKEN", "reason": "Test", "policy": stripePolicy}, "ready")
	f.lifecycleCall("wait_for_secret", map[string]any{"name": "TOKEN"}, "ready")
	f.lifecycleCall("list_secrets", nil, "listed")
	f.lifecycleCall("forget_secret", map[string]any{"name": "TOKEN"}, "forgotten")
	for _, out := range f.outputs {
		if strings.Contains(out, "example.com") {
			t.Fatalf("unredacted metadata: %s", out)
		}
	}
}

func TestWaitCancellationKeepsRequestOpen(t *testing.T) {
	f := newFixture(t)
	f.h.set("ignore", "")
	f.s.wait = time.Millisecond
	f.lifecycleCall("request_secret", map[string]any{"name": "TOKEN", "reason": "Test", "policy": stripePolicy}, "pending")
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, _, _ := f.s.waitForSecret(ctx, nil, nameInput{Name: "TOKEN"})
	if res.StructuredContent.(map[string]any)["status"] != "pending" {
		t.Fatal("tool cancellation ended the human's request")
	}
	f.lifecycleCall("forget_secret", map[string]any{"name": "TOKEN"}, "forgotten")
}

func TestWaitUsesCurrentRequestInsteadOfOlderReadyPolicy(t *testing.T) {
	f := newFixture(t)
	f.fillSecret("TOKEN")
	f.h.set("ignore", "")
	f.s.wait = time.Millisecond
	newPolicy := map[string]any{"hosts": []string{"api.github.com"}, "methods": []string{"GET"}}
	f.lifecycleCall("request_secret", map[string]any{"name": "TOKEN", "reason": "Replace policy", "policy": newPolicy}, "pending")
	f.lifecycleCall("wait_for_secret", map[string]any{"name": "TOKEN"}, "pending")
	f.s.mu.Lock()
	fr := f.s.fills["TOKEN"]
	f.s.mu.Unlock()
	if err := fr.req.FillExternal([]byte(testSecret)); err != nil {
		t.Fatal(err)
	}
	f.lifecycleCall("wait_for_secret", map[string]any{"name": "TOKEN"}, "ready")
	for _, info := range f.s.store.List() {
		if info.Name == "TOKEN" && info.Policy.Hosts[0] != "api.github.com" {
			t.Fatal("wait returned the older policy")
		}
	}
	f.assertNoLeak()
}

func TestSupersededLocalPageCannotRefillForgottenName(t *testing.T) {
	f := newFixture(t)
	f.h.set("ignore", "")
	f.s.wait = time.Millisecond
	f.lifecycleCall("request_secret", map[string]any{"name": "TOKEN", "reason": "Test", "policy": stripePolicy}, "pending")
	f.s.mu.Lock()
	old := f.s.fills["TOKEN"]
	f.s.mu.Unlock()
	f.lifecycleCall("request_secret", map[string]any{"name": "TOKEN", "reason": "Replace policy", "policy": map[string]any{"hosts": []string{"api.github.com"}}}, "pending")
	f.s.mu.Lock()
	current := f.s.fills["TOKEN"]
	f.s.mu.Unlock()
	f.lifecycleCall("forget_secret", map[string]any{"name": "TOKEN"}, "forgotten")
	for _, fr := range []*fillRequest{old, current} {
		if err := fr.req.FillExternal([]byte(testSecret)); err == nil {
			t.Fatal("a superseded page refilled a forgotten name")
		}
	}
	if f.s.store.Has("TOKEN") {
		t.Fatal("forgotten value returned")
	}
}

func TestLifecycleRedactsHTMLCharactersBeforeJSONDecode(t *testing.T) {
	f := newFixture(t)
	value := "<placeholder&value>"
	f.h.set("fill", value)
	pol := map[string]any{"hosts": []string{"example.com"}, "paths": []string{"/v1/" + value}}
	f.lifecycleCall("request_secret", map[string]any{"name": "TOKEN", "reason": "Test", "policy": pol}, "ready")
	res, err := f.cs.CallTool(f.ctx, &mcp.CallToolParams{Name: "list_secrets"})
	if err != nil {
		t.Fatal(err)
	}
	assertRedacted := func(v any) {
		b, _ := json.Marshal(v)
		var decoded any
		if err := json.Unmarshal(b, &decoded); err != nil {
			t.Fatal(err)
		}
		// Inspect decoded strings as well as wire bytes; escaped HTML is still a value.
		if strings.Contains(fmt.Sprint(decoded), value) {
			t.Fatal("decoded metadata revealed the value")
		}
	}
	assertRedacted(res.StructuredContent)
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			var decoded any
			if err := json.Unmarshal([]byte(tc.Text), &decoded); err != nil {
				t.Fatal(err)
			}
			assertRedacted(decoded)
		}
	}
}
