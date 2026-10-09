package main

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"secrethandoff.com/cli/internal/appcard"
	"secrethandoff.com/cli/internal/relay"
)

const testSecret = "ghp_TestOnlyValue9xK2mQ7vL4pR8sW3nZ6"

// human answers pages that the binary opens. action is "fill", "decline",
// "approve", "deny", or "ignore".
type human struct {
	mu        sync.Mutex
	action    string
	value     string
	opened    int
	phoneLink chan string
}

func (h *human) set(action, value string) {
	h.mu.Lock()
	h.action, h.value = action, value
	h.mu.Unlock()
}

func (h *human) open(pageURL string) error {
	h.mu.Lock()
	h.opened++
	action, value := h.action, h.value
	h.mu.Unlock()
	if action == "ignore" {
		return nil
	}
	origin, token, _ := strings.Cut(pageURL, "/r#")
	go func() {
		jar, _ := cookiejar.New(nil)
		c := &http.Client{Jar: jar, Timeout: 5 * time.Second}
		get, _ := http.NewRequest("GET", origin+"/api/request", nil)
		get.Header.Set("X-Secrethandoff-Token", token)
		if res, err := c.Do(get); err == nil {
			res.Body.Close()
		}
		if action == "phone" {
			post, _ := http.NewRequest("POST", origin+"/api/relay", strings.NewReader("{}"))
			post.Header.Set("X-Secrethandoff-Token", token)
			post.Header.Set("Origin", origin)
			post.Header.Set("Content-Type", "application/json")
			if res, err := c.Do(post); err == nil {
				var info struct {
					Link string `json:"link"`
				}
				json.NewDecoder(res.Body).Decode(&info)
				res.Body.Close()
				h.phoneLink <- info.Link
			}
			return
		}
		body, _ := json.Marshal(map[string]string{"value": value})
		post, _ := http.NewRequest("POST", origin+"/api/"+action, bytes.NewReader(body))
		post.Header.Set("X-Secrethandoff-Token", token)
		post.Header.Set("Origin", origin)
		post.Header.Set("Content-Type", "application/json")
		if res, err := c.Do(post); err == nil {
			res.Body.Close()
		}
	}()
	return nil
}

type fixture struct {
	t       *testing.T
	s       *session
	h       *human
	cs      *mcp.ClientSession
	ctx     context.Context
	outputs []string
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	return newFixtureWith(t, nil)
}

func newFixtureWith(t *testing.T, clientOpts *mcp.ClientOptions) *fixture {
	return newFixtureClient(t, clientOpts, &mcp.Implementation{Name: "test", Version: "1"})
}

func newFixtureClient(t *testing.T, clientOpts *mcp.ClientOptions, info *mcp.Implementation) *fixture {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	t.Cleanup(cancel)
	h := &human{action: "fill", value: testSecret}
	s := newSession()
	s.open, s.available, s.wait = h.open, func() error { return nil }, 3*time.Second
	t.Cleanup(s.close)
	serverSide, clientSide := mcp.NewInMemoryTransports()
	ss, err := newMCPServer(s).Connect(ctx, serverSide, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ss.Close() })
	cs, err := mcp.NewClient(info, clientOpts).Connect(ctx, clientSide, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return &fixture{t: t, s: s, h: h, cs: cs, ctx: ctx}
}

// call runs a tool and records its text, so every test can assert that no
// output contains the secret.
func (f *fixture) call(name string, args map[string]any) (string, bool) {
	f.t.Helper()
	res, err := f.cs.CallTool(f.ctx, &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		f.t.Fatalf("%s: %v", name, err)
	}
	var b strings.Builder
	for _, c := range res.Content {
		if tc, ok := c.(*mcp.TextContent); ok {
			b.WriteString(tc.Text)
		}
	}
	metadata, _ := json.Marshal(res.StructuredContent)
	f.outputs = append(f.outputs, b.String()+"\n"+string(metadata))
	return b.String(), res.IsError
}

func (f *fixture) assertNoLeak() {
	f.t.Helper()
	b64 := base64.StdEncoding.EncodeToString([]byte(testSecret))
	for _, out := range f.outputs {
		if strings.Contains(out, testSecret) || strings.Contains(out, b64) || strings.Contains(out, fmt.Sprintf("%x", testSecret)) {
			f.t.Fatalf("a tool output contains the secret: %q", out)
		}
	}
}

var stripePolicy = map[string]any{"hosts": []string{"example.com"}}

func (f *fixture) fillSecret(name string) {
	f.t.Helper()
	out, isErr := f.call("request_secret", map[string]any{"name": name, "reason": "Test", "policy": stripePolicy})
	if isErr || !strings.Contains(out, name+" is ready") {
		f.t.Fatalf("request_secret: %s", out)
	}
}

func TestHandshakeAndTools(t *testing.T) {
	f := newFixture(t)
	init := f.cs.InitializeResult()
	if init.ServerInfo.Name != "secrethandoff" || init.Instructions != serverInstructions {
		t.Fatalf("initialize: %+v", init.ServerInfo)
	}
	tools, err := f.cs.ListTools(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range tools.Tools {
		names = append(names, tool.Name)
		if strings.Contains(tool.Description, serverInstructions) {
			t.Fatalf("%s duplicates shared server instructions", tool.Name)
		}
	}
	if strings.Join(names, ",") != "confirm_secret,forget_secret,http_request,list_secrets,proxy_settings,request_secret,run_with_secret,wait_for_secret" {
		t.Fatalf("tools = %v", names)
	}
}

func TestAppCard(t *testing.T) {
	f := newFixture(t)
	tools, err := f.cs.ListTools(f.ctx, nil)
	if err != nil {
		t.Fatal(err)
	}
	linked := map[string]bool{}
	for _, tool := range tools.Tools {
		if ui, ok := tool.Meta["ui"].(map[string]any); ok && ui["resourceUri"] == appcard.URI {
			linked[tool.Name] = true
		}
	}
	if len(linked) != 4 || !linked["request_secret"] || !linked["wait_for_secret"] || !linked["run_with_secret"] || !linked["confirm_secret"] {
		t.Fatalf("tools linked to the card: %v", linked)
	}
	res, err := f.cs.ReadResource(f.ctx, &mcp.ReadResourceParams{URI: appcard.URI})
	if err != nil || len(res.Contents) != 1 {
		t.Fatalf("read card: %v %v", res, err)
	}
	c := res.Contents[0]
	if c.MIMEType != "text/html;profile=mcp-app" || !strings.Contains(c.Text, "ui/initialize") || !strings.Contains(c.Text, "Secret Handoff") {
		t.Fatalf("card: %s %.80s", c.MIMEType, c.Text)
	}
	// The card takes no input and makes no requests.
	for _, banned := range []string{"<input", "<textarea", "fetch(", "XMLHttpRequest", "WebSocket", "innerHTML"} {
		if strings.Contains(c.Text, banned) {
			t.Errorf("card contains %q", banned)
		}
	}
}

func TestRequestSecretFlows(t *testing.T) {
	f := newFixture(t)
	f.fillSecret("API_KEY")
	if out, _ := f.call("list_secrets", nil); !strings.Contains(out, `"API_KEY"`) {
		t.Fatalf("list: %s", out)
	}
	// Same name and policy: ready at once, no new page.
	opened := f.h.opened
	f.fillSecret("API_KEY")
	if f.h.opened != opened {
		t.Fatal("a ready secret opened a new page")
	}

	f.h.set("ignore", "")
	f.s.wait = 100 * time.Millisecond
	if out, _ := f.call("request_secret", map[string]any{"name": "SLOW", "reason": "Test", "policy": stripePolicy}); !strings.Contains(out, "Waiting for the user") {
		t.Fatalf("pending: %s", out)
	}
	if out, _ := f.call("request_secret", map[string]any{"name": "SLOW", "reason": "Test", "policy": stripePolicy}); !strings.Contains(out, "Waiting") || f.h.opened != opened+1 {
		t.Fatalf("a second call must rejoin the open request: %s (opened %d)", out, f.h.opened)
	}

	f.s.wait = 3 * time.Second
	f.h.set("decline", "")
	if out, _ := f.call("request_secret", map[string]any{"name": "NOPE", "reason": "Test", "policy": stripePolicy}); !strings.Contains(out, "declined") {
		t.Fatalf("decline: %s", out)
	}
	for _, bad := range []map[string]any{
		{"name": "bad name", "reason": "x", "policy": stripePolicy},
		{"name": "OK", "reason": "x", "policy": map[string]any{"hosts": []string{"10.0.0.1"}}},
		{"name": "OK", "reason": strings.Repeat("x", 600), "policy": stripePolicy},
	} {
		if _, isErr := f.call("request_secret", bad); !isErr {
			t.Fatalf("accepted %v", bad)
		}
	}
	if out, _ := f.call("forget_secret", map[string]any{"name": "API_KEY"}); !strings.Contains(out, "erased") {
		t.Fatalf("forget: %s", out)
	}
	f.assertNoLeak()
}

// newTLSAPI starts a test API that answers as example.com and points the
// session's HTTP client at it.
func newTLSAPI(t *testing.T, f *fixture, handler http.HandlerFunc) {
	t.Helper()
	ts := httptest.NewTLSServer(handler)
	t.Cleanup(ts.Close)
	pool := x509.NewCertPool()
	pool.AddCert(ts.Certificate())
	f.s.client = newHTTPClient(&tls.Config{RootCAs: pool})
	tr := f.s.client.Transport.(*http.Transport)
	tr.Proxy = nil
	tr.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != "example.com:443" {
			return nil, fmt.Errorf("test dialer refuses %s", addr)
		}
		return (&net.Dialer{}).DialContext(ctx, network, ts.Listener.Addr().String())
	}
}

func TestHTTPRequest(t *testing.T) {
	f := newFixture(t)
	newTLSAPI(t, f, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/redirect":
			http.Redirect(w, r, "https://elsewhere.example.org/steal", http.StatusFound)
		default:
			ok := r.Header.Get("Authorization") == "Bearer "+testSecret && r.URL.Query().Get("key") == testSecret
			body, _ := io.ReadAll(r.Body)
			w.Header().Set("Content-Type", "application/json")
			json.NewEncoder(w).Encode(map[string]any{"ok": ok, "echo": r.Header.Get("Authorization"), "body": string(body)})
		}
	})
	f.fillSecret("TOKEN")
	out, isErr := f.call("http_request", map[string]any{
		"method": "POST", "url": "https://example.com/v1/check?key={{secret:TOKEN}}",
		"headers": map[string]string{"Authorization": "Bearer {{secret:TOKEN}}"},
		"body":    `{"token":"{{secret:TOKEN}}"}`,
	})
	if isErr || !strings.Contains(out, `"ok":true`) || !strings.Contains(out, "[REDACTED:TOKEN]") || !strings.Contains(out, "removed from the response") {
		t.Fatalf("http_request: %s", out)
	}
	if out, _ = f.call("http_request", map[string]any{"method": "GET", "url": "https://example.com/redirect", "headers": map[string]string{"Authorization": "Bearer {{secret:TOKEN}}"}}); !strings.Contains(out, "HTTP 302") || !strings.Contains(out, "not followed") {
		t.Fatalf("redirect: %s", out)
	}
	refused := []map[string]any{
		{"method": "GET", "url": "https://example.com/{{secret:TOKEN}}"},
		{"method": "GET", "url": "https://{{secret:TOKEN}}.example.com/"},
		{"method": "GET", "url": "https://example.com/plain"},
		{"method": "GET", "url": "https://other.example.org/?k={{secret:TOKEN}}"},
		{"method": "GET", "url": "http://example.com/?k={{secret:TOKEN}}"},
		{"method": "GET", "url": "https://httpbin.org/anything?k={{secret:TOKEN}}"},
		{"method": "GET", "url": "https://example.com/?k={{secret:MISSING}}"},
		{"method": "GET", "url": "https://example.com/", "headers": map[string]string{"Host": "{{secret:TOKEN}}"}},
	}
	for _, args := range refused {
		if out, isErr := f.call("http_request", args); !isErr {
			t.Errorf("accepted %v: %s", args, out)
		}
	}
	f.assertNoLeak()
}

// TestHelperProcess is the command that run_with_secret starts in tests.
func TestHelperProcess(t *testing.T) {
	if os.Getenv("SECRETHANDOFF_TEST_HELPER") != "1" {
		return
	}
	v := os.Getenv("MY_TOKEN")
	fmt.Printf("raw=%s b64=%s len=%d\n", v, base64.StdEncoding.EncodeToString([]byte(v)), len(v))
	os.Exit(3)
}

func TestRunWithSecret(t *testing.T) {
	f := newFixture(t)
	f.fillSecret("TOKEN")
	t.Setenv("SECRETHANDOFF_TEST_HELPER", "1")
	args := map[string]any{"command": []string{os.Args[0], "-test.run=^TestHelperProcess$"}, "secrets": []string{"TOKEN:MY_TOKEN"}}

	f.h.set("deny", "")
	if out, _ := f.call("run_with_secret", args); !strings.Contains(out, "did not approve") {
		t.Fatalf("deny: %s", out)
	}
	f.h.set("approve", "")
	out, _ := f.call("run_with_secret", args)
	if !strings.Contains(out, "exit code: 3") || !strings.Contains(out, fmt.Sprintf("len=%d", len(testSecret))) || !strings.Contains(out, "raw=[REDACTED:TOKEN]") {
		t.Fatalf("run: %s", out)
	}
	for _, bad := range []map[string]any{
		{"command": []string{"true"}, "secrets": []string{"TOKEN:PATH"}},
		{"command": []string{"true"}, "secrets": []string{"TOKEN:LD_PRELOAD"}},
		{"command": []string{"true"}, "secrets": []string{"MISSING:X"}},
		{"command": []string{"true"}, "secrets": []string{"TOKEN:lower"}},
		{"command": []string{"true"}, "secrets": []string{}},
		{"command": []string{}, "secrets": []string{"TOKEN:X"}},
	} {
		if out, isErr := f.call("run_with_secret", bad); !isErr {
			t.Errorf("accepted %v: %s", bad, out)
		}
	}
	f.assertNoLeak()
}

func TestProxySettings(t *testing.T) {
	f := newFixture(t)
	if _, isErr := f.call("proxy_settings", nil); !isErr {
		t.Fatal("proxy_settings worked with no secret")
	}
	f.fillSecret("TOKEN")
	out, isErr := f.call("proxy_settings", nil)
	if isErr || !strings.Contains(out, "HTTPS_PROXY=http://sh:") || !strings.Contains(out, "SSL_CERT_FILE=") || !strings.Contains(out, "example.com") {
		t.Fatalf("proxy_settings: %s", out)
	}
	file := strings.Fields(strings.SplitN(out, "SSL_CERT_FILE=", 2)[1])[0]
	if b, err := os.ReadFile(file); err != nil || !strings.Contains(string(b), "BEGIN CERTIFICATE") || strings.Contains(string(b), "PRIVATE") {
		t.Fatalf("CA file: %v", err)
	}
	f.assertNoLeak()
}

// TestPhoneFill covers phase 2: the human presses "Fill on my phone
// instead", a phone seals the secret for the link's key, and the binary
// picks it up through a (fake) relay.
func TestPhoneFill(t *testing.T) {
	f := newFixture(t)
	var mu sync.Mutex
	var created map[string]any
	var ciphertext string
	cancelled := false
	relaySrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case r.URL.Path == "/api/requests":
			json.NewDecoder(r.Body).Decode(&created)
			w.WriteHeader(http.StatusCreated)
			json.NewEncoder(w).Encode(map[string]string{"id": "PHONEPHONEPHONEPHONE01"})
		case strings.HasSuffix(r.URL.Path, "/pickup"):
			if ciphertext == "" {
				w.WriteHeader(http.StatusAccepted)
				json.NewEncoder(w).Encode(map[string]string{"state": "pending"})
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"state": "picked_up", "ciphertext": ciphertext})
			ciphertext = "used"
		case strings.HasSuffix(r.URL.Path, "/cancel"):
			cancelled = true
			json.NewEncoder(w).Encode(map[string]string{"state": "cancelled"})
		}
	}))
	defer relaySrv.Close()
	f.s.relayURL = relaySrv.URL
	f.h.phoneLink = make(chan string, 1)
	f.h.set("phone", "")
	f.s.wait = 10 * time.Second

	done := make(chan string, 1)
	go func() {
		out, _ := f.call("request_secret", map[string]any{"name": "PHONE_KEY", "reason": "Phone test", "policy": stripePolicy})
		done <- out
	}()
	link := <-f.h.phoneLink
	if !strings.HasPrefix(link, relaySrv.URL+"/q/PHONEPHONEPHONEPHONE01#v1.") {
		t.Fatalf("link = %s", link)
	}
	parts := strings.Split(strings.SplitN(link, "#", 2)[1], ".")
	pubBytes, _ := base64.RawURLEncoding.DecodeString(parts[1])
	pk, err := hpke.DHKEM(ecdh.P256()).NewPublicKey(pubBytes)
	if err != nil {
		t.Fatal(err)
	}
	mu.Lock()
	expires := int64(created["expiresAt"].(float64))
	ct, err := hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), relay.Info("PHONEPHONEPHONEPHONE01", parts[3], expires), []byte(testSecret))
	ciphertext = base64.RawURLEncoding.EncodeToString(ct)
	mu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if out := <-done; !strings.Contains(out, "PHONE_KEY is ready") {
		t.Fatalf("request_secret: %s", out)
	}
	if !f.s.store.Has("PHONE_KEY") {
		t.Fatal("the phone value was not stored")
	}
	// The pickup consumed the relay request, so there is nothing to cancel.
	time.Sleep(3 * time.Second)
	mu.Lock()
	if cancelled {
		t.Error("a picked-up request was cancelled")
	}
	mu.Unlock()

	// When the local page wins, the binary withdraws the relay request.
	mu.Lock()
	ciphertext, cancelled = "", false
	mu.Unlock()
	f.h.set("phone", "")
	go func() {
		out, _ := f.call("request_secret", map[string]any{"name": "LOCAL_WINS", "reason": "Phone test", "policy": stripePolicy})
		done <- out
	}()
	<-f.h.phoneLink
	f.s.mu.Lock()
	local := f.s.fills["LOCAL_WINS"].req
	f.s.mu.Unlock()
	if err := local.FillExternal([]byte("filled-on-the-computer")); err != nil {
		t.Fatal(err)
	}
	if out := <-done; !strings.Contains(out, "LOCAL_WINS is ready") {
		t.Fatalf("request_secret: %s", out)
	}
	deadline := time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		c := cancelled
		mu.Unlock()
		if c {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if !cancelled {
		t.Fatal("the relay request was not withdrawn after the local fill")
	}
	f.assertNoLeak()
}

func TestClientLabel(t *testing.T) {
	cases := map[*mcp.Implementation]string{
		nil: "",
		{Name: "claude-code", Version: "2.1.293"}:       "claude-code 2.1.293",
		{Name: "x", Title: "Claude Code", Version: "2"}: "Claude Code 2",
		{Name: "evil‮edoc​\n", Version: "1"}:            "eviledoc 1",
		{Name: strings.Repeat("a", 200)}:                strings.Repeat("a", 80),
	}
	for in, want := range cases {
		if got := clientLabel(in); got != want {
			t.Errorf("clientLabel(%v) = %q, want %q", in, got, want)
		}
	}
}
