package main

import (
	"context"
	"crypto/ecdh"
	"crypto/hpke"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"secrethandoff.com/cli/internal/relay"
)

// fakeRelay accepts one request and returns a ciphertext once the test
// "phone" sets one.
type fakeRelay struct {
	mu           sync.Mutex
	srv          *httptest.Server
	created      map[string]any
	ct           string
	id           string
	beforePickup func()
}

func newFakeRelay(t *testing.T) *fakeRelay {
	f := &fakeRelay{id: "REMOTEREMOTEREMOTER001"}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasSuffix(r.URL.Path, "/pickup") {
			f.mu.Lock()
			hook := f.beforePickup
			f.mu.Unlock()
			if hook != nil {
				hook()
			}
		}
		f.mu.Lock()
		defer f.mu.Unlock()
		switch {
		case r.URL.Path == "/api/requests":
			json.NewDecoder(r.Body).Decode(&f.created)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"id": f.id})
		case strings.HasSuffix(r.URL.Path, "/pickup"):
			if f.ct == "" {
				w.WriteHeader(http.StatusAccepted)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"state": "picked_up", "ciphertext": f.ct})
		}
	}))
	t.Cleanup(f.srv.Close)
	return f
}

// fillFromPhone seals value for the link's key and returns the
// confirmation code that the phone page would show.
func (f *fakeRelay) fillFromPhone(t *testing.T, link, value string) string {
	t.Helper()
	parts := strings.Split(strings.SplitN(link, "#", 2)[1], ".")
	pub, _ := base64.RawURLEncoding.DecodeString(parts[1])
	pk, err := hpke.DHKEM(ecdh.P256()).NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	ct, err := hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), relay.Info(f.id, parts[3], int64(f.created["expiresAt"].(float64))), []byte(value))
	if err != nil {
		t.Fatal(err)
	}
	f.ct = base64.RawURLEncoding.EncodeToString(ct)
	return relay.ConfirmationCode(f.id, ct)
}

func remoteFixture(t *testing.T, opts *mcp.ClientOptions) (*fixture, *fakeRelay) {
	f := newFixtureWith(t, opts)
	fr := newFakeRelay(t)
	f.s.relayURL = fr.srv.URL
	f.s.available = func() error { return errNoDisplay }
	f.s.wait = 300 * time.Millisecond
	return f, fr
}

func linkIn(text string) string {
	for _, field := range strings.Fields(text) {
		if strings.Contains(field, "/q/") && strings.Contains(field, "#v1.") {
			return field
		}
	}
	return ""
}

func TestRemoteModeTextFallback(t *testing.T) {
	f, fr := remoteFixture(t, nil)
	args := map[string]any{"name": "CLOUD_KEY", "reason": "Cloud test", "policy": stripePolicy}
	out, _ := f.call("request_secret", args)
	link := linkIn(out)
	if link == "" || !strings.Contains(out, "pairing code") {
		t.Fatalf("first call: %s", out)
	}
	code := fr.fillFromPhone(t, link, testSecret)
	out, _ = f.call("request_secret", args)
	if !strings.Contains(out, "confirm_secret") {
		t.Fatalf("after fill: %s", out)
	}
	// The secret is not usable before confirmation.
	if _, isErr := f.call("http_request", map[string]any{"method": "GET", "url": "https://example.com/?k={{secret:CLOUD_KEY}}"}); !isErr {
		t.Fatal("an unconfirmed secret was usable")
	}
	if out, isErr := f.call("confirm_secret", map[string]any{"name": "CLOUD_KEY", "code": "AAA-AAAA"}); !isErr || !strings.Contains(out, "4 attempts remain") {
		t.Fatalf("wrong code: %s", out)
	}
	if out, isErr := f.call("confirm_secret", map[string]any{"name": "CLOUD_KEY", "code": strings.ToLower(code)}); isErr || !strings.Contains(out, "CLOUD_KEY is ready") {
		t.Fatalf("right code: %s", out)
	}
	if !f.s.store.Has("CLOUD_KEY") {
		t.Fatal("the confirmed secret was not stored")
	}
	for _, o := range f.outputs {
		if strings.Contains(o, code) {
			t.Fatalf("a tool output revealed the confirmation code: %s", o)
		}
	}
	f.assertNoLeak()
}

func TestRemoteModeDiscardsAfterWrongCodes(t *testing.T) {
	f, fr := remoteFixture(t, nil)
	args := map[string]any{"name": "CLOUD_KEY", "reason": "Cloud test", "policy": stripePolicy}
	out, _ := f.call("request_secret", args)
	fr.fillFromPhone(t, linkIn(out), testSecret)
	f.call("request_secret", args)
	for i := 0; i < maxConfirmAttempts; i++ {
		f.call("confirm_secret", map[string]any{"name": "CLOUD_KEY", "code": "ZZZ-ZZZZ"})
	}
	if out, _ := f.call("confirm_secret", map[string]any{"name": "CLOUD_KEY", "code": "ZZZ-ZZZZ"}); !strings.Contains(out, "no filled request") {
		t.Fatalf("after five wrong codes: %s", out)
	}
	if f.s.store.Has("CLOUD_KEY") {
		t.Fatal("a value was stored after five wrong codes")
	}
}

func TestRemoteModeURLElicitation(t *testing.T) {
	elicited := make(chan *mcp.ElicitParams, 1)
	opts := &mcp.ClientOptions{
		Capabilities: &mcp.ClientCapabilities{Elicitation: &mcp.ElicitationCapabilities{URL: &mcp.URLElicitationCapabilities{}}},
		ElicitationHandler: func(_ context.Context, req *mcp.ElicitRequest) (*mcp.ElicitResult, error) {
			elicited <- req.Params
			return &mcp.ElicitResult{Action: "accept"}, nil
		},
	}
	f, fr := remoteFixture(t, opts)
	out, _ := f.call("request_secret", map[string]any{"name": "CLOUD_KEY", "reason": "Cloud test", "policy": stripePolicy})
	p := <-elicited
	if p.Mode != "url" || !strings.Contains(p.URL, "/q/"+fr.id+"#v1.") {
		t.Fatalf("elicitation: %+v", p)
	}
	// The link went to the client's UI, not into the model context.
	// On protocol 2026-07-28 the client shows the page and retries the call,
	// which then waits for the fill.
	if strings.Contains(out, "#v1.") || !(strings.Contains(out, "showing a page") || strings.Contains(out, "Waiting for the user")) {
		t.Fatalf("tool result: %s", out)
	}
}

func TestWaitForRemoteSecretAndStructuredStates(t *testing.T) {
	f, fr := remoteFixture(t, nil)
	out, _ := f.call("request_secret", map[string]any{"name": "CLOUD_KEY", "reason": "Cloud test", "policy": stripePolicy})
	code := fr.fillFromPhone(t, linkIn(out), testSecret)
	data := f.lifecycleCall("wait_for_secret", map[string]any{"name": "CLOUD_KEY"}, "confirmation_required")
	if data["presentation"] != "remote_link" || data["next_tool"] != "confirm_secret" {
		t.Fatalf("remote metadata: %v", data)
	}
	listed := f.lifecycleCall("list_secrets", nil, "listed")
	pending := listed["pending"].([]any)
	if len(pending) != 1 || pending[0].(map[string]any)["status"] != "confirmation_required" {
		t.Fatalf("remote listing: %v", listed)
	}
	if f.s.store.Has("CLOUD_KEY") {
		t.Fatal("wait bypassed confirmation")
	}
	f.lifecycleCall("confirm_secret", map[string]any{"name": "CLOUD_KEY", "code": code}, "ready")
	f.lifecycleCall("wait_for_secret", map[string]any{"name": "CLOUD_KEY"}, "ready")
	f.lifecycleCall("forget_secret", map[string]any{"name": "CLOUD_KEY"}, "forgotten")
	for _, out := range f.outputs {
		if strings.Contains(out, code) {
			t.Fatal("structured result revealed the confirmation code")
		}
	}
	f.assertNoLeak()
}

func TestForgetRemoteDuringPickupDoesNotRestoreValue(t *testing.T) {
	f, fr := remoteFixture(t, nil)
	out, _ := f.call("request_secret", map[string]any{"name": "CLOUD_KEY", "reason": "Cloud test", "policy": stripePolicy})
	fr.fillFromPhone(t, linkIn(out), testSecret)
	started, release := make(chan struct{}), make(chan struct{})
	fr.mu.Lock()
	fr.beforePickup = func() { close(started); <-release }
	fr.mu.Unlock()
	f.s.mu.Lock()
	rr := f.s.remotes["CLOUD_KEY"]
	f.s.mu.Unlock()
	finished := make(chan *mcp.CallToolResult, 1)
	go func() { finished <- f.s.waitRemote(f.ctx, "CLOUD_KEY", rr) }()
	<-started
	f.lifecycleCall("forget_secret", map[string]any{"name": "CLOUD_KEY"}, "forgotten")
	close(release)
	res := <-finished
	if res.StructuredContent.(map[string]any)["status"] != "cancelled" {
		t.Fatalf("late pickup: %v", res)
	}
	rr.mu.Lock()
	defer rr.mu.Unlock()
	if rr.value != nil || f.s.store.Has("CLOUD_KEY") {
		t.Fatal("late pickup restored a forgotten value")
	}
}

func TestRemoteWaitCancellationKeepsRequest(t *testing.T) {
	f, _ := remoteFixture(t, nil)
	f.call("request_secret", map[string]any{"name": "CLOUD_KEY", "reason": "Cloud test", "policy": stripePolicy})
	f.s.mu.Lock()
	rr := f.s.remotes["CLOUD_KEY"]
	f.s.mu.Unlock()
	ctx, cancel := context.WithCancel(f.ctx)
	cancel()
	res := f.s.waitRemote(ctx, "CLOUD_KEY", rr)
	if res.StructuredContent.(map[string]any)["status"] != "pending" {
		t.Fatalf("cancelled wait: %v", res)
	}
	f.s.mu.Lock()
	kept := f.s.remotes["CLOUD_KEY"] == rr
	f.s.mu.Unlock()
	if !kept {
		t.Fatal("tool cancellation removed the human's request")
	}
}

func TestOldRemoteWaiterCannotRemoveReplacement(t *testing.T) {
	f, _ := remoteFixture(t, nil)
	args := map[string]any{"name": "CLOUD_KEY", "reason": "Cloud test", "policy": stripePolicy}
	f.call("request_secret", args)
	f.s.mu.Lock()
	old := f.s.remotes["CLOUD_KEY"]
	f.s.mu.Unlock()
	f.lifecycleCall("forget_secret", map[string]any{"name": "CLOUD_KEY"}, "forgotten")
	f.call("request_secret", args)
	f.s.mu.Lock()
	replacement := f.s.remotes["CLOUD_KEY"]
	f.s.mu.Unlock()
	res := f.s.waitRemote(f.ctx, "CLOUD_KEY", old)
	if res.StructuredContent.(map[string]any)["status"] != "cancelled" {
		t.Fatalf("old waiter: %v", res)
	}
	f.s.mu.Lock()
	kept := f.s.remotes["CLOUD_KEY"] == replacement
	f.s.mu.Unlock()
	if !kept {
		t.Fatal("an old waiter removed the replacement request")
	}
}

func TestSupersededRemoteRequestDiscardsUnconfirmedValue(t *testing.T) {
	f, fr := remoteFixture(t, nil)
	out, _ := f.call("request_secret", map[string]any{"name": "CLOUD_KEY", "reason": "Cloud test", "policy": stripePolicy})
	fr.fillFromPhone(t, linkIn(out), testSecret)
	f.lifecycleCall("wait_for_secret", map[string]any{"name": "CLOUD_KEY"}, "confirmation_required")
	f.s.mu.Lock()
	old := f.s.remotes["CLOUD_KEY"]
	f.s.mu.Unlock()
	f.call("request_secret", map[string]any{"name": "CLOUD_KEY", "reason": "Replace policy", "policy": map[string]any{"hosts": []string{"api.github.com"}}})
	old.mu.Lock()
	discarded := old.value == nil && old.failed == "cancelled"
	old.mu.Unlock()
	if !discarded {
		t.Fatal("superseded request retained an unconfirmed value")
	}
	f.assertNoLeak()
}
