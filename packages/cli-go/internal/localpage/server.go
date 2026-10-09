// Package localpage serves the fill and approval pages on the loopback
// address (ADR 0009, threat model T-42, T-43, T-44).
package localpage

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"time"

	"secrethandoff.com/cli/internal/loopback"
	"secrethandoff.com/cli/internal/policy"
)

//go:embed assets
var assets embed.FS

// Kind is the type of a page request.
type Kind string

const (
	KindFill    Kind = "fill"
	KindApprove Kind = "approve"
)

// State is the state of a page request. Only Pending can change, except that
// a filled or approved request can become Rejected through "This was not me".
type State string

const (
	Pending  State = "pending"
	Filled   State = "filled"
	Declined State = "declined"
	Approved State = "approved"
	Denied   State = "denied"
	Rejected State = "rejected"
	Expired  State = "expired"
)

const (
	maxPending   = 20
	maxBodyBytes = 64 * 1024
	tokenHeader  = "X-Secrethandoff-Token"
	claimPrefix  = "sh_claim_"
	maxValueLen  = 32 * 1024
)

// RelayInfo is what the local page shows for phone fill: a QR code of the
// relay link and the pairing code. It goes only to the page, never to the
// agent (ADR 0010).
type RelayInfo struct {
	QRSVG       string `json:"qr_svg"`
	PairingCode string `json:"pairing_code"`
	Link        string `json:"link"`
}

// RelayStarter creates a relay request for phone fill when the human asks.
type RelayStarter func() (RelayInfo, error)

// FillHandler receives a submitted value. The value is wiped after it
// returns, so the handler must copy what it keeps.
type FillHandler func(value []byte) error

// Request is one fill or approval page.
type Request struct {
	Kind    Kind
	Name    string
	Reason  string
	Policy  policy.Policy
	Command []string
	Dir     string
	Secrets []string
	Expires time.Time

	onFill   FillHandler
	onReject func()
	onRelay  RelayStarter
	relay    *RelayInfo
	viaPhone bool

	mu        sync.Mutex
	state     State
	cookie    string
	starting  bool
	relayErr  string
	claimHash [32]byte
	claimed   bool
	done      chan struct{}
}

// State returns the current state.
func (r *Request) State() State {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.state
}

// Done is closed when the request leaves Pending.
func (r *Request) Done() <-chan struct{} { return r.done }

// Cancel closes the fill page before its caller erases the stored value.
// It shares the fill mutex. An old filled page also becomes Rejected, so
// its later "This was not me" action cannot erase a replacement by name.
func (r *Request) Cancel() {
	r.mu.Lock()
	defer r.mu.Unlock()
	switch r.state {
	case Pending:
		r.state = Rejected
		close(r.done)
	case Filled:
		r.state = Rejected
	}
}

// Server is the loopback page server for one MCP session.
type Server struct {
	ln   net.Listener
	srv  *http.Server
	host string
	open func(url string) error

	mu    sync.Mutex
	reqs  map[[32]byte]*Request
	about About
}

// About tells the human which agent client asks and which binary serves the
// page. The client reports its own name, so it is context, not proof.
type About struct {
	Client  string `json:"client,omitempty"`
	Version string `json:"version"`
	// Isolated is true when pages open in the isolated browser window.
	Isolated bool `json:"isolated"`
}

// SetAbout sets what every page shows about the client and the binary.
func (s *Server) SetAbout(a About) {
	s.mu.Lock()
	s.about = a
	s.mu.Unlock()
}

// Start binds 127.0.0.1 on a random port. open shows a URL in the browser.
func Start(open func(url string) error) (*Server, error) {
	ln, err := loopback.Listen()
	if err != nil {
		return nil, err
	}
	s := &Server{ln: ln, host: ln.Addr().String(), open: open, reqs: map[[32]byte]*Request{}}
	s.srv = &http.Server{Handler: s.routes(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 15 * time.Second, WriteTimeout: 15 * time.Second}
	go s.srv.Serve(ln) //nolint:errcheck // Serve returns when Close is called
	return s, nil
}

// Close stops the server and expires every pending request.
func (s *Server) Close() error {
	s.mu.Lock()
	for _, r := range s.reqs {
		r.finish(Expired)
	}
	s.reqs = map[[32]byte]*Request{}
	s.mu.Unlock()
	return s.srv.Close()
}

// Origin is the page origin, for tests.
func (s *Server) Origin() string { return "http://" + s.host }

// NewFill creates a fill request and opens its page. onFill stores the value.
// onReject runs when the human says that a fill was not theirs.
func (s *Server) NewFill(name, reason string, p policy.Policy, ttl time.Duration, onFill FillHandler, onReject func()) (*Request, error) {
	r := &Request{Kind: KindFill, Name: name, Reason: reason, Policy: p, onFill: onFill, onReject: onReject}
	return r, s.add(r, ttl)
}

// SetRelayStarter enables "Fill on my phone instead" for a fill request.
func (r *Request) SetRelayStarter(start RelayStarter) {
	r.mu.Lock()
	r.onRelay = start
	r.mu.Unlock()
}

// RelayFailed tells the page that phone fill stopped working.
func (r *Request) RelayFailed(msg string) {
	r.mu.Lock()
	r.relayErr = msg
	r.mu.Unlock()
}

// FillExternal completes a pending fill request with a value that arrived
// another way, such as through the relay. The value is wiped afterwards.
func (r *Request) FillExternal(value []byte) error {
	defer wipe(value)
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != Pending {
		return fmt.Errorf("this request is already %s", r.state)
	}
	if err := r.onFill(value); err != nil {
		return err
	}
	r.state, r.viaPhone = Filled, true
	close(r.done)
	return nil
}

// NewApproval creates a command approval request and opens its page.
func (s *Server) NewApproval(command []string, dir string, secretNames []string, ttl time.Duration) (*Request, error) {
	r := &Request{Kind: KindApprove, Command: command, Dir: dir, Secrets: secretNames}
	return r, s.add(r, ttl)
}

func (s *Server) add(r *Request, ttl time.Duration) error {
	token := make([]byte, 32)
	if _, err := rand.Read(token); err != nil {
		return err
	}
	encoded := base64.RawURLEncoding.EncodeToString(token)
	r.state, r.done, r.Expires = Pending, make(chan struct{}), time.Now().Add(ttl)
	key := sha256.Sum256([]byte(encoded))
	// Each request has its own claim cookie. Cookies on 127.0.0.1 do not
	// separate ports, so one shared name let requests steal each other's
	// claim.
	r.cookie = claimPrefix + fmt.Sprintf("%x", key[:6])

	s.mu.Lock()
	pending := 0
	for _, x := range s.reqs {
		if x.State() == Pending {
			pending++
		}
	}
	if pending >= maxPending {
		s.mu.Unlock()
		return errors.New("too many open requests; finish or decline some first")
	}
	s.reqs[key] = r
	s.mu.Unlock()

	time.AfterFunc(ttl, func() { r.finish(Expired) })
	// The token goes only to the browser launcher, never to a tool result,
	// stdout, or stderr (AGENTS.md, local binary invariants).
	if err := s.open(s.Origin() + "/r#" + encoded); err != nil {
		r.finish(Expired)
		return err
	}
	return nil
}

func (r *Request) finish(st State) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != Pending {
		return false
	}
	r.state = st
	close(r.done)
	return true
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /r", s.static("assets/page.html", "text/html; charset=utf-8"))
	mux.HandleFunc("GET /page.js", s.static("assets/page.js", "text/javascript; charset=utf-8"))
	mux.HandleFunc("GET /page.css", s.static("assets/page.css", "text/css; charset=utf-8"))
	mux.HandleFunc("GET /favicon.svg", s.static("assets/favicon.svg", "image/svg+xml"))
	mux.HandleFunc("GET /api/request", s.handleGet)
	mux.HandleFunc("POST /api/fill", s.handleAction)
	mux.HandleFunc("POST /api/decline", s.handleAction)
	mux.HandleFunc("POST /api/approve", s.handleAction)
	mux.HandleFunc("POST /api/deny", s.handleAction)
	mux.HandleFunc("POST /api/not-me", s.handleNotMe)
	mux.HandleFunc("POST /api/relay", s.handleRelay)
	return s.guard(mux)
}

// agentBrowsers matches the user agents of browsers that an AI agent reads
// and drives: the browser pane of the Claude desktop app ("Claude/<version>"
// beside "Chrome/"). The binary opens the system browser, so the page reaches
// such a browser only when the agent opens it there.
var agentBrowsers = regexp.MustCompile(`\bClaude/[0-9][^ ]* .*Chrome/|\bChrome/.*\bClaude/[0-9]`)

// AgentBrowser reports whether userAgent is a browser that an agent controls.
func AgentBrowser(userAgent string) bool { return agentBrowsers.MatchString(userAgent) }

// guard applies the loopback checks to every request (threat model T-43).
func (s *Server) guard(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; form-action 'none'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Frame-Options", "DENY")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Cache-Control", "no-store")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		h.Set("Cross-Origin-Resource-Policy", "same-origin")
		// DNS rebinding: a page on another name that resolves to 127.0.0.1
		// sends its own name in Host.
		if req.Host != s.host {
			http.Error(w, "wrong host", http.StatusMisdirectedRequest)
			return
		}
		if site := req.Header.Get("Sec-Fetch-Site"); site != "" && site != "same-origin" && site != "none" {
			http.Error(w, "cross-site request", http.StatusForbidden)
			return
		}
		// A browser that the agent can read and drive must not claim or fill
		// a request (threat model T-54). The page explains this itself.
		if strings.HasPrefix(req.URL.Path, "/api/") && AgentBrowser(req.Header.Get("User-Agent")) {
			http.Error(w, "agent-controlled browser", http.StatusForbidden)
			return
		}
		if req.Method == http.MethodPost {
			if req.Header.Get("Origin") != s.Origin() {
				http.Error(w, "wrong origin", http.StatusForbidden)
				return
			}
			if !strings.HasPrefix(req.Header.Get("Content-Type"), "application/json") {
				http.Error(w, "JSON required", http.StatusUnsupportedMediaType)
				return
			}
			req.Body = http.MaxBytesReader(w, req.Body, maxBodyBytes)
		}
		next.ServeHTTP(w, req)
	})
}

func (s *Server) static(name, contentType string) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		b, err := assets.ReadFile(name)
		if err != nil {
			http.NotFound(w, nil)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Write(b) //nolint:errcheck
	}
}

func (s *Server) lookup(req *http.Request) *Request {
	token := req.Header.Get(tokenHeader)
	if len(token) != 43 {
		return nil
	}
	key := sha256.Sum256([]byte(token))
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.reqs[key]
}

type view struct {
	Kind        Kind      `json:"kind"`
	State       State     `json:"state"`
	Name        string    `json:"name,omitempty"`
	Reason      string    `json:"reason,omitempty"`
	Policy      string    `json:"policy,omitempty"`
	Wildcard    bool      `json:"wildcard,omitempty"`
	Command     []string  `json:"command,omitempty"`
	Dir         string    `json:"dir,omitempty"`
	Secrets     []string  `json:"secrets,omitempty"`
	Expires     time.Time `json:"expires"`
	ClaimedHere bool      `json:"claimed_here"`
	ClaimedElse bool      `json:"claimed_elsewhere"`
	PhoneFill   bool      `json:"phone_fill_available"`
	ViaPhone    bool      `json:"via_phone,omitempty"`
	PhoneError  string    `json:"phone_error,omitempty"`
	About       About     `json:"about"`
}

// handleGet returns the request for display. The first browser that loads
// it claims it with a cookie; actions need that claim (threat model T-42).
func (s *Server) handleGet(w http.ResponseWriter, req *http.Request) {
	r := s.lookup(req)
	if r == nil {
		http.Error(w, "unknown request", http.StatusNotFound)
		return
	}
	here := r.claimedBy(req)
	s.mu.Lock()
	about := s.about
	s.mu.Unlock()
	r.mu.Lock()
	if !r.claimed && r.state == Pending {
		claim := make([]byte, 32)
		if _, err := rand.Read(claim); err == nil {
			value := base64.RawURLEncoding.EncodeToString(claim)
			r.claimHash, r.claimed, here = sha256.Sum256([]byte(value)), true, true
			http.SetCookie(w, &http.Cookie{Name: r.cookie, Value: value, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		}
	}
	v := view{Kind: r.Kind, State: r.state, Name: r.Name, Reason: r.Reason, Command: r.Command, Dir: r.Dir, Secrets: r.Secrets, Expires: r.Expires, ClaimedHere: here, ClaimedElse: r.claimed && !here, PhoneFill: r.onRelay != nil, ViaPhone: r.viaPhone, PhoneError: r.relayErr, About: about}
	r.mu.Unlock()
	if r.Kind == KindFill {
		v.Policy, v.Wildcard = r.Policy.Describe(), r.Policy.HasWildcard()
	}
	writeJSON(w, v)
}

func (r *Request) claimedBy(req *http.Request) bool {
	c, err := req.Cookie(r.cookie)
	if err != nil {
		return false
	}
	h := sha256.Sum256([]byte(c.Value))
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.claimed && subtle.ConstantTimeCompare(h[:], r.claimHash[:]) == 1
}

func (s *Server) handleAction(w http.ResponseWriter, req *http.Request) {
	r := s.lookup(req)
	if r == nil {
		http.Error(w, "unknown request", http.StatusNotFound)
		return
	}
	if !r.claimedBy(req) {
		http.Error(w, "this request was opened in another window", http.StatusConflict)
		return
	}
	action := strings.TrimPrefix(req.URL.Path, "/api/")
	var err error
	switch {
	case action == "fill" && r.Kind == KindFill:
		err = r.fill(req.Body)
	case action == "decline" && r.Kind == KindFill:
		err = r.transition(Declined)
	case action == "approve" && r.Kind == KindApprove:
		err = r.transition(Approved)
	case action == "deny" && r.Kind == KindApprove:
		err = r.transition(Denied)
	default:
		err = errors.New("action does not match this request")
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusConflict)
		return
	}
	writeJSON(w, map[string]State{"state": r.State()})
}

func (r *Request) transition(st State) error {
	if !r.finish(st) {
		return fmt.Errorf("this request is already %s", r.State())
	}
	return nil
}

func (r *Request) fill(body io.Reader) error {
	var in struct {
		Value string `json:"value"`
	}
	if err := json.NewDecoder(body).Decode(&in); err != nil {
		return errors.New("invalid request body")
	}
	value := []byte(in.Value)
	in.Value = ""
	defer wipe(value)
	if len(value) == 0 || len(value) > maxValueLen {
		return fmt.Errorf("the secret must be 1 to %d bytes", maxValueLen)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.state != Pending {
		return fmt.Errorf("this request is already %s", r.state)
	}
	if err := r.onFill(value); err != nil {
		return err
	}
	r.state = Filled
	close(r.done)
	return nil
}

// handleRelay starts phone fill. Only the claimant can start it, and the
// QR code and pairing code go back only to the page.
func (s *Server) handleRelay(w http.ResponseWriter, req *http.Request) {
	r := s.lookup(req)
	if r == nil {
		http.Error(w, "unknown request", http.StatusNotFound)
		return
	}
	if !r.claimedBy(req) {
		http.Error(w, "this request was opened in another window", http.StatusConflict)
		return
	}
	r.mu.Lock()
	start, existing, state, starting := r.onRelay, r.relay, r.state, r.starting
	if existing == nil && !starting {
		r.starting = true
	}
	r.mu.Unlock()
	if state != Pending || start == nil {
		http.Error(w, "phone fill is not available for this request", http.StatusConflict)
		return
	}
	if existing == nil && starting {
		// A second press while the first one creates the relay request.
		http.Error(w, "phone fill is starting; try again in a moment", http.StatusConflict)
		return
	}
	if existing == nil {
		info, err := start()
		r.mu.Lock()
		r.starting = false
		if err == nil {
			r.relay = &info
		}
		existing = r.relay
		r.mu.Unlock()
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
	}
	writeJSON(w, existing)
}

// handleNotMe lets the human cancel a fill or approval that they did not
// make. It needs only the token, so a human whose page lost the claim can
// still use it. Cancelling is always safe.
func (s *Server) handleNotMe(w http.ResponseWriter, req *http.Request) {
	r := s.lookup(req)
	if r == nil {
		http.Error(w, "unknown request", http.StatusNotFound)
		return
	}
	r.mu.Lock()
	prev := r.state
	switch prev {
	case Pending:
		r.state = Rejected
		close(r.done)
	case Filled, Approved:
		r.state = Rejected
	}
	if (prev == Filled || prev == Approved) && r.onReject != nil {
		// Keep rejection serialized with Cancel and fill. Otherwise a callback
		// from an old page could run after a name was forgotten and reused.
		r.onReject()
	}
	r.mu.Unlock()
	writeJSON(w, map[string]State{"state": r.State()})
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v) //nolint:errcheck
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
