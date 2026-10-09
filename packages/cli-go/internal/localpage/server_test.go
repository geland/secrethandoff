package localpage

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/cookiejar"
	"strings"
	"sync"
	"testing"
	"time"

	"secrethandoff.com/cli/internal/policy"
)

const secretValue = "correct-horse-battery-staple-9f3k"

type harness struct {
	t      *testing.T
	s      *Server
	mu     sync.Mutex
	opened []string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t}
	s, err := Start(func(url string) error { h.mu.Lock(); h.opened = append(h.opened, url); h.mu.Unlock(); return nil })
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	h.s = s
	return h
}

func (h *harness) lastToken() string {
	h.mu.Lock()
	defer h.mu.Unlock()
	u := h.opened[len(h.opened)-1]
	if !strings.HasPrefix(u, h.s.Origin()+"/r#") {
		h.t.Fatalf("opened %q", u)
	}
	return strings.SplitN(u, "#", 2)[1]
}

func newClient() *http.Client {
	jar, _ := cookiejar.New(nil)
	return &http.Client{Jar: jar, Timeout: 5 * time.Second}
}

func (h *harness) do(c *http.Client, method, path, token string, body any, mutate func(*http.Request)) (int, string) {
	h.t.Helper()
	var r io.Reader
	if body != nil {
		b, _ := json.Marshal(body)
		r = bytes.NewReader(b)
	}
	req, _ := http.NewRequest(method, h.s.Origin()+path, r)
	if token != "" {
		req.Header.Set(tokenHeader, token)
	}
	if method == http.MethodPost {
		req.Header.Set("Origin", h.s.Origin())
		req.Header.Set("Content-Type", "application/json")
	}
	if mutate != nil {
		mutate(req)
	}
	res, err := c.Do(req)
	if err != nil {
		h.t.Fatal(err)
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	if res.Header.Get("Access-Control-Allow-Origin") != "" {
		h.t.Fatal("CORS header sent")
	}
	if !strings.Contains(res.Header.Get("Content-Security-Policy"), "default-src 'none'") {
		h.t.Fatal("missing CSP")
	}
	return res.StatusCode, string(b)
}

func testPolicy(t *testing.T) policy.Policy {
	p, err := policy.Parse(policy.Policy{Hosts: []string{"api.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func TestFillFlow(t *testing.T) {
	h := newHarness(t)
	var got []byte
	r, err := h.s.NewFill("API_KEY", "Deploy needs it", testPolicy(t), time.Minute, func(v []byte) error { got = append([]byte(nil), v...); return nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	tok := h.lastToken()
	human := newClient()
	if code, body := h.do(human, "GET", "/r", "", nil, nil); code != 200 || !strings.Contains(body, "page.js") || !strings.Contains(body, "Secret Handoff") {
		t.Fatalf("page: %d", code)
	}
	if code, body := h.do(human, "GET", "/favicon.svg", "", nil, nil); code != 200 || !strings.Contains(body, "<svg") {
		t.Fatalf("favicon: %d", code)
	}
	h.s.SetAbout(About{Client: "test-client 1.0", Version: "9.9.9"})
	code, body := h.do(human, "GET", "/api/request", tok, nil, nil)
	if code != 200 || !strings.Contains(body, `"claimed_here":true`) || !strings.Contains(body, "api.example.com") ||
		!strings.Contains(body, `"about":{"client":"test-client 1.0","version":"9.9.9","isolated":false}`) {
		t.Fatalf("view: %d %s", code, body)
	}
	if code, body = h.do(human, "POST", "/api/fill", tok, map[string]string{"value": secretValue}, nil); code != 200 {
		t.Fatalf("fill: %d %s", code, body)
	}
	<-r.Done()
	if r.State() != Filled || string(got) != secretValue {
		t.Fatalf("state %s", r.State())
	}
	if code, _ = h.do(human, "POST", "/api/fill", tok, map[string]string{"value": "second"}, nil); code != http.StatusConflict {
		t.Fatalf("second fill: %d", code)
	}
	if _, body = h.do(human, "GET", "/api/request", tok, nil, nil); strings.Contains(body, secretValue) {
		t.Fatal("a response contains the secret")
	}
}

func TestLoopbackGuards(t *testing.T) {
	h := newHarness(t)
	_, err := h.s.NewFill("API_KEY", "", testPolicy(t), time.Minute, func([]byte) error { return nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	tok := h.lastToken()
	c := newClient()
	cases := []struct {
		name   string
		method string
		path   string
		tok    string
		mutate func(*http.Request)
		want   int
	}{
		{"dns rebinding host", "GET", "/api/request", tok, func(r *http.Request) { r.Host = "evil.test:80" }, http.StatusMisdirectedRequest},
		{"cross-site fetch", "GET", "/api/request", tok, func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, http.StatusForbidden},
		{"foreign origin", "POST", "/api/decline", tok, func(r *http.Request) { r.Header.Set("Origin", "https://evil.test") }, http.StatusForbidden},
		{"form post", "POST", "/api/decline", tok, func(r *http.Request) { r.Header.Set("Content-Type", "application/x-www-form-urlencoded") }, http.StatusUnsupportedMediaType},
		{"no token", "GET", "/api/request", "", nil, http.StatusNotFound},
		{"wrong token", "GET", "/api/request", strings.Repeat("A", 43), nil, http.StatusNotFound},
	}
	for _, tc := range cases {
		if code, _ := h.do(c, tc.method, tc.path, tc.tok, map[string]string{}, tc.mutate); code != tc.want {
			t.Errorf("%s: got %d, want %d", tc.name, code, tc.want)
		}
	}
}

// TestClaimConflict covers threat model T-42: another client that uses the
// token first claims the request, and the human can cancel it.
func TestClaimConflict(t *testing.T) {
	h := newHarness(t)
	rejected := false
	r, err := h.s.NewFill("API_KEY", "", testPolicy(t), time.Minute, func([]byte) error { return nil }, func() { rejected = true })
	if err != nil {
		t.Fatal(err)
	}
	tok := h.lastToken()
	intruder, human := newClient(), newClient()
	h.do(intruder, "GET", "/api/request", tok, nil, nil)
	if code, body := h.do(human, "GET", "/api/request", tok, nil, nil); !strings.Contains(body, `"claimed_elsewhere":true`) || code != 200 {
		t.Fatalf("human view: %s", body)
	}
	if code, _ := h.do(human, "POST", "/api/fill", tok, map[string]string{"value": secretValue}, nil); code != http.StatusConflict {
		t.Fatal("an unclaimed client filled the request")
	}
	if code, _ := h.do(intruder, "POST", "/api/fill", tok, map[string]string{"value": "attacker"}, nil); code != 200 {
		t.Fatal("claimant could not fill")
	}
	if code, _ := h.do(human, "POST", "/api/not-me", tok, map[string]string{}, nil); code != 200 {
		t.Fatal("not-me failed")
	}
	if r.State() != Rejected || !rejected {
		t.Fatalf("state %s, rejected %v", r.State(), rejected)
	}
}

func TestApprovalAndExpiry(t *testing.T) {
	h := newHarness(t)
	a, err := h.s.NewApproval([]string{"psql", "-c", "select 1"}, "/tmp", []string{"DB_PASSWORD"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	c := newClient()
	tok := h.lastToken()
	h.do(c, "GET", "/api/request", tok, nil, nil)
	if code, _ := h.do(c, "POST", "/api/fill", tok, map[string]string{"value": "x"}, nil); code != http.StatusConflict {
		t.Fatal("fill accepted on an approval request")
	}
	if code, _ := h.do(c, "POST", "/api/approve", tok, map[string]string{}, nil); code != 200 || a.State() != Approved {
		t.Fatalf("approve failed: %s", a.State())
	}
	e, err := h.s.NewFill("SHORT", "", testPolicy(t), 50*time.Millisecond, func([]byte) error { return nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	select {
	case <-e.Done():
	case <-time.After(2 * time.Second):
		t.Fatal("request did not expire")
	}
	if e.State() != Expired {
		t.Fatalf("state %s", e.State())
	}
}

func TestOpenerFailureExpiresRequest(t *testing.T) {
	s, err := Start(func(string) error { return io.ErrClosedPipe })
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	r, err := s.NewFill("X_KEY", "", testPolicy(t), time.Minute, func([]byte) error { return nil }, nil)
	if err == nil || r.State() != Expired {
		t.Fatal("a failed browser launch must fail the request")
	}
}

// TestAgentBrowserCannotClaim: the Claude desktop browser pane is refused
// before it claims the request, so the human's own browser still can.
func TestAgentBrowserCannotClaim(t *testing.T) {
	const pane = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Claude/2.26454.2 Chrome/152.0.7977.130 Safari/537.36"
	for ua, want := range map[string]bool{
		pane: true,
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/152.0.0.0 Safari/537.36": false,
		"Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:150.0) Gecko/20100101 Firefox/150.0":                                  false,
		"Claude/1.0 (a CLI, not a browser)": false,
	} {
		if got := AgentBrowser(ua); got != want {
			t.Errorf("AgentBrowser(%q) = %v", ua, got)
		}
	}
	h := newHarness(t)
	if _, err := h.s.NewFill("API_KEY", "Deploy needs it", testPolicy(t), time.Minute, func([]byte) error { return nil }, nil); err != nil {
		t.Fatal(err)
	}
	tok := h.lastToken()
	setPane := func(r *http.Request) { r.Header.Set("User-Agent", pane) }
	if code, _ := h.do(newClient(), "GET", "/api/request", tok, nil, setPane); code != http.StatusForbidden {
		t.Fatalf("pane GET: %d", code)
	}
	if code, _ := h.do(newClient(), "POST", "/api/fill", tok, map[string]string{"value": "x"}, setPane); code != http.StatusForbidden {
		t.Fatalf("pane fill: %d", code)
	}
	if code, body := h.do(newClient(), "GET", "/api/request", tok, nil, nil); code != 200 || !strings.Contains(body, `"claimed_here":true`) {
		t.Fatalf("own browser after the pane: %d %s", code, body)
	}
}
