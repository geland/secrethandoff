package localpage

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/coder/websocket"
)

func presenceDial(t *testing.T, h *harness, token string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, res, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(h.s.Origin(), "http")+"/api/presence", &websocket.DialOptions{
		HTTPHeader:   http.Header{"Origin": {h.s.Origin()}},
		Subprotocols: []string{"secrethandoff.presence", "sh-token." + token},
	})
	if err != nil {
		t.Fatal("could not connect the presence socket")
	}
	if conn.Subprotocol() != "secrethandoff.presence" || strings.Contains(res.Header.Get("Sec-WebSocket-Protocol"), token) {
		t.Fatal("presence must negotiate only its fixed protocol")
	}
	t.Cleanup(func() { conn.CloseNow() })
	return conn
}

func presenceEvent(t *testing.T, events <-chan bool, want bool) {
	t.Helper()
	select {
	case got := <-events:
		if got != want {
			t.Fatal("unexpected presence event")
		}
	case <-time.After(3 * time.Second):
		t.Fatal("missing presence event")
	}
}

func TestPresenceTracksManyTabsWithoutClaimingOrBlockingFill(t *testing.T) {
	h := newHarness(t)
	events := make(chan bool, 32)
	h.s.SetPagePresence(func() func() {
		events <- true
		return func() { events <- false }
	})
	r, err := h.s.NewFill("API_KEY", "Synthetic browser lifetime test", testPolicy(t), time.Minute, func([]byte) error { return nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	token := h.lastToken()
	var sockets []*websocket.Conn
	// More than HTTP/1's six per-origin connections. Presence must leave the
	// regular request and fill endpoints available.
	for range 8 {
		sockets = append(sockets, presenceDial(t, h, token))
		presenceEvent(t, events, true)
	}
	if r.claimed || r.State() != Pending {
		t.Fatal("presence changed the request")
	}
	client := newClient()
	if code, _ := h.do(client, "GET", "/api/request", token, nil, nil); code != 200 {
		t.Fatal("request blocked")
	}
	if code, _ := h.do(client, "POST", "/api/fill", token, map[string]string{"value": secretValue}, nil); code != 200 {
		t.Fatal("fill blocked")
	}
	if r.State() != Filled {
		t.Fatal("fill did not finish")
	}
	for _, conn := range sockets {
		conn.CloseNow()
		presenceEvent(t, events, false)
	}
	// A final-state page still tracks lifetime, including a reload.
	presenceDial(t, h, token)
	presenceEvent(t, events, true)
	h.s.Close()
	presenceEvent(t, events, false)
}

func TestPresenceRejectsUntrustedConnections(t *testing.T) {
	h := newHarness(t)
	_, err := h.s.NewFill("API_KEY", "Synthetic browser lifetime test", testPolicy(t), time.Minute, func([]byte) error { return nil }, nil)
	if err != nil {
		t.Fatal(err)
	}
	token := h.lastToken()
	h.s.SetPagePresence(func() func() { t.Error("untrusted connection held the browser open"); return func() {} })
	for _, tc := range []struct {
		name   string
		mutate func(*http.Request)
		code   int
	}{
		{"missing token", func(r *http.Request) { r.Header.Set("Origin", h.s.Origin()) }, 404},
		{"token only in URL", func(r *http.Request) { r.Header.Set("Origin", h.s.Origin()); r.URL.RawQuery = "token=" + token }, 404},
		{"missing origin", func(r *http.Request) {
			r.Header.Set("Sec-WebSocket-Protocol", "secrethandoff.presence, sh-token."+token)
		}, 403},
		{"wrong origin", func(r *http.Request) {
			r.Header.Set("Origin", "http://example.invalid")
			r.Header.Set("Sec-WebSocket-Protocol", "secrethandoff.presence, sh-token."+token)
		}, 403},
		{"wrong host", func(r *http.Request) { r.Host = "example.invalid" }, 421},
		{"agent browser", func(r *http.Request) { r.Header.Set("User-Agent", "Chrome/100 Claude/1.0") }, 403},
		{"cross site", func(r *http.Request) { r.Header.Set("Sec-Fetch-Site", "cross-site") }, 403},
		{"not a websocket", func(r *http.Request) {
			r.Header.Set("Origin", h.s.Origin())
			r.Header.Set("Sec-WebSocket-Protocol", "secrethandoff.presence, sh-token."+token)
		}, 426},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if code, _ := h.do(newClient(), "GET", "/api/presence", "", nil, tc.mutate); code != tc.code {
				t.Fatalf("status %d", code)
			}
		})
	}
}
