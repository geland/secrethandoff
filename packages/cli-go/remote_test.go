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
	mu      sync.Mutex
	srv     *httptest.Server
	created map[string]any
	ct      string
	id      string
}

func newFakeRelay(t *testing.T) *fakeRelay {
	f := &fakeRelay{id: "REMOTEREMOTEREMOTER001"}
	f.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
