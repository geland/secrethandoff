package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var groupArgs = map[string]any{"name": "LOGIN", "reason": "Dummy grouped credential test", "policy": stripePolicy, "secrets": []map[string]string{{"name": "LOGIN_USER", "label": "Username"}, {"name": "LOGIN_PASS", "label": "Password"}}}
var groupValues = map[string]string{"LOGIN_USER": "dummy-group-username-7fg2", "LOGIN_PASS": "dummy-group-password-8hk3"}

type groupPage struct {
	client        *http.Client
	origin, token string
}

func newGroupFixture(t *testing.T) (*fixture, chan string) {
	f := newFixture(t)
	f.s.wait = time.Millisecond
	pages := make(chan string, 20)
	f.s.open = func(u string) error { pages <- u; return nil }
	return f, pages
}
func claimGroupPage(t *testing.T, raw string) *groupPage {
	t.Helper()
	origin, token, ok := strings.Cut(raw, "/r#")
	if !ok {
		t.Fatal("invalid test page")
	}
	jar, _ := cookiejar.New(nil)
	p := &groupPage{&http.Client{Jar: jar, Timeout: 5 * time.Second}, origin, token}
	req, _ := http.NewRequest("GET", origin+"/api/request", nil)
	req.Header.Set("X-Secrethandoff-Token", token)
	res, err := p.client.Do(req)
	if err != nil {
		t.Fatal("could not claim test page")
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		t.Fatal("test page was not available")
	}
	return p
}
func (p *groupPage) post(action string, data any) int {
	b, _ := json.Marshal(data)
	req, _ := http.NewRequest("POST", p.origin+"/api/"+action, bytes.NewReader(b))
	req.Header.Set("X-Secrethandoff-Token", p.token)
	req.Header.Set("Origin", p.origin)
	req.Header.Set("Content-Type", "application/json")
	res, err := p.client.Do(req)
	if err != nil {
		return 0
	}
	io.Copy(io.Discard, res.Body)
	res.Body.Close()
	return res.StatusCode
}
func assertGroupClean(t *testing.T, outputs ...string) {
	t.Helper()
	for _, output := range outputs {
		for _, value := range groupValues {
			for _, form := range leakForms(value) {
				if strings.Contains(output, form) {
					t.Fatal("group value appeared in output")
				}
			}
		}
	}
}
func TestGroupedLifecycleAndValidation(t *testing.T) {
	f, pages := newGroupFixture(t)
	data := f.lifecycleCall("request_secrets", groupArgs, "pending")
	if data["next_arguments"].(map[string]any)["name"] != "LOGIN" || len(data["names"].([]any)) != 2 {
		t.Fatal("missing group metadata")
	}
	page := claimGroupPage(t, <-pages)
	f.lifecycleCall("request_secrets", groupArgs, "pending")
	if len(pages) != 0 {
		t.Fatal("rejoining opened a second page")
	}
	f.lifecycleCall("wait_for_secret", map[string]any{"name": "LOGIN_PASS"}, "pending")
	for _, invalid := range []map[string]string{{"LOGIN_USER": "x"}, {"LOGIN_USER": "x", "LOGIN_PASS": ""}, {"LOGIN_USER": "x", "LOGIN_PASS": "y", "EXTRA": "z"}, {"LOGIN_USER": strings.Repeat("x", 32768), "LOGIN_PASS": "x"}} {
		if page.post("fill", map[string]any{"values": invalid}) == 200 || len(f.s.store.List()) != 0 {
			t.Fatal("partial or invalid group was published")
		}
	}
	if page.post("fill", map[string]string{"value": "one field is not a group"}) == 200 {
		t.Fatal("single fill accepted for group")
	}
	if page.post("relay", map[string]any{}) == 200 {
		t.Fatal("group unexpectedly enabled phone fill")
	}
	if page.post("fill", map[string]any{"values": groupValues}) != 200 {
		t.Fatal("group fill failed")
	}
	f.lifecycleCall("wait_for_secret", map[string]any{"name": "LOGIN"}, "ready")
	f.lifecycleCall("request_secrets", groupArgs, "ready")
	if len(f.s.store.List()) != 2 || len(pages) != 0 {
		t.Fatal("ready group did not reuse both values")
	}
	if page.post("fill", map[string]any{"values": groupValues}) == 200 {
		t.Fatal("group filled twice")
	}
	f.lifecycleCall("list_secrets", nil, "listed")
	f.lifecycleCall("forget_secret", map[string]any{"name": "LOGIN_PASS"}, "forgotten")
	if len(f.s.store.List()) != 0 {
		t.Fatal("forget left a grouped credential")
	}
	f.lifecycleCall("wait_for_secret", map[string]any{"name": "LOGIN"}, "missing")
	if page.post("fill", map[string]any{"values": groupValues}) == 200 {
		t.Fatal("old form restored group")
	}
	assertGroupClean(t, f.outputs...)
}
func TestGroupedInputBoundsAndNoHeadlessFallback(t *testing.T) {
	for _, fields := range [][]map[string]string{nil, {{"name": "A"}}, {{"name": "A"}, {"name": "A"}}, {{"name": "LOGIN"}, {"name": "B"}}, {{"name": "bad name"}, {"name": "B"}}, {{"name": "A", "label": "bad\u202elabel"}, {"name": "B"}}, {{"name": "A", "label": strings.Repeat("x", 81)}, {"name": "B"}}} {
		f, pages := newGroupFixture(t)
		args := map[string]any{"name": "LOGIN", "reason": "Test", "policy": stripePolicy, "secrets": fields}
		if _, isErr := f.call("request_secrets", args); !isErr || len(pages) != 0 {
			t.Fatal("invalid fields created a page")
		}
	}
	f, pages := newGroupFixture(t)
	fields := make([]map[string]string, 9)
	for i := range fields {
		fields[i] = map[string]string{"name": fmt.Sprintf("FIELD%d", i)}
	}
	if _, isErr := f.call("request_secrets", map[string]any{"name": "LOGIN", "reason": "Test", "policy": stripePolicy, "secrets": fields}); !isErr {
		t.Fatal("accepted nine fields")
	}
	f.s.available = func() error { return fmt.Errorf("no display") }
	if _, isErr := f.call("request_secrets", groupArgs); !isErr || len(pages) != 0 || len(f.s.remotes) != 0 {
		t.Fatal("headless group silently used relay")
	}
}
func TestGroupedConcurrentFillAndForget(t *testing.T) {
	for range 12 {
		f, pages := newGroupFixture(t)
		f.lifecycleCall("request_secrets", groupArgs, "pending")
		p := claimGroupPage(t, <-pages)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() { defer wg.Done(); p.post("fill", map[string]any{"values": groupValues}) }()
		f.lifecycleCall("forget_secret", map[string]any{"name": "LOGIN"}, "forgotten")
		wg.Wait()
		if len(f.s.store.List()) != 0 {
			t.Fatal("fill resurrected cancelled group")
		}
		assertGroupClean(t, f.outputs...)
	}
}
func TestGroupedEightFieldsAndSupersession(t *testing.T) {
	f, pages := newGroupFixture(t)
	fields := make([]map[string]string, 8)
	values := map[string]string{}
	for i := range fields {
		name := fmt.Sprintf("FIELD%d", i)
		fields[i] = map[string]string{"name": name}
		values[name] = "dummy-value"
	}
	f.lifecycleCall("request_secrets", map[string]any{"name": "EIGHT", "reason": "Test", "policy": stripePolicy, "secrets": fields}, "pending")
	p := claimGroupPage(t, <-pages)
	if p.post("fill", map[string]any{"values": values}) != 200 || len(f.s.store.List()) != 8 {
		t.Fatal("eight-field limit failed")
	}
	f.lifecycleCall("request_secret", map[string]any{"name": "FIELD0", "reason": "Replace", "policy": map[string]any{"hosts": []string{"api.github.com"}}}, "pending")
	if len(f.s.store.List()) != 0 {
		t.Fatal("superseding a group member left siblings")
	}
	_ = p.post("not-me", map[string]any{})
	if len(f.s.store.List()) != 0 {
		t.Fatal("old group action changed replacement")
	}
}
func TestGroupedCommandProcess(t *testing.T) {
	if os.Getenv("SECRETHANDOFF_GROUP_HELPER") != "1" {
		return
	}
	fmt.Print(os.Getenv("GROUP_USER"))
	fmt.Fprint(os.Stderr, os.Getenv("GROUP_PASS"))
	os.Exit(0)
}
func TestGroupedValuesWorkTogetherAndAreRedacted(t *testing.T) {
	f, pages := newGroupFixture(t)
	f.lifecycleCall("request_secrets", groupArgs, "pending")
	p := claimGroupPage(t, <-pages)
	if p.post("fill", map[string]any{"values": groupValues}) != 200 {
		t.Fatal("fill failed")
	}
	t.Setenv("SECRETHANDOFF_GROUP_HELPER", "1")
	f.s.wait = time.Second
	dir, _ := os.Getwd()
	done := make(chan *mcp.CallToolResult, 1)
	go func() {
		r, err := f.cs.CallTool(f.ctx, &mcp.CallToolParams{Name: "run_with_secret", Arguments: map[string]any{"command": []string{os.Args[0], "-test.run=^TestGroupedCommandProcess$"}, "dir": dir, "secrets": []string{"LOGIN_USER:GROUP_USER", "LOGIN_PASS:GROUP_PASS"}}})
		if err != nil {
			done <- nil
			return
		}
		done <- r
	}()
	approval := claimGroupPage(t, <-pages)
	if approval.post("approve", map[string]any{}) != 200 {
		t.Fatal("browser approval failed")
	}
	r := <-done
	if r == nil {
		t.Fatal("command failed")
	}
	b, _ := json.Marshal(r)
	if !strings.Contains(string(b), "[REDACTED:LOGIN_USER]") || !strings.Contains(string(b), "[REDACTED:LOGIN_PASS]") {
		t.Fatal("command did not receive both fields")
	}
	assertGroupClean(t, string(b))
	f.lifecycleCall("forget_secret", map[string]any{"name": "LOGIN"}, "forgotten")
	assertGroupClean(t, f.outputs...)
}

func TestGroupedPolicyChangeAndOldRejectionCannotEraseReplacement(t *testing.T) {
	f, pages := newGroupFixture(t)
	f.lifecycleCall("request_secrets", groupArgs, "pending")
	old := claimGroupPage(t, <-pages)
	args := map[string]any{}
	for key, value := range groupArgs {
		args[key] = value
	}
	args["policy"] = map[string]any{"hosts": []string{"api.github.com"}, "methods": []string{"GET"}}
	f.lifecycleCall("request_secrets", args, "pending")
	current := claimGroupPage(t, <-pages)
	if old.post("fill", map[string]any{"values": groupValues}) == 200 {
		t.Fatal("superseded group accepted values")
	}
	if current.post("fill", map[string]any{"values": groupValues}) != 200 {
		t.Fatal("replacement group failed")
	}
	_ = old.post("not-me", map[string]any{})
	if len(f.s.store.List()) != 2 {
		t.Fatal("old group erased replacement")
	}
	for _, info := range f.s.store.List() {
		if info.Policy.Hosts[0] != "api.github.com" {
			t.Fatal("group used an old policy")
		}
	}
	f.lifecycleCall("forget_secret", map[string]any{"name": "LOGIN"}, "forgotten")
	assertGroupClean(t, f.outputs...)
}
func TestGroupedPendingListAndHumanDecline(t *testing.T) {
	f, pages := newGroupFixture(t)
	f.lifecycleCall("request_secrets", groupArgs, "pending")
	p := claimGroupPage(t, <-pages)
	listed := f.lifecycleCall("list_secrets", nil, "listed")
	pending := listed["pending"].([]any)
	if len(pending) != 1 || len(pending[0].(map[string]any)["names"].([]any)) != 2 {
		t.Fatal("group pending aliases were duplicated or missing")
	}
	if p.post("decline", map[string]any{}) != 200 {
		t.Fatal("could not decline group")
	}
	f.lifecycleCall("wait_for_secret", map[string]any{"name": "LOGIN_USER"}, "declined")
	if p.post("fill", map[string]any{"values": groupValues}) == 200 || len(f.s.store.List()) != 0 {
		t.Fatal("declined group accepted values")
	}
}
