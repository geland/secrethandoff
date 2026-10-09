// Package proxy is the optional local HTTPS proxy (plan phase 1.5). Agent
// commands send requests through it with {{secret:NAME}} references. The
// proxy checks each secret's policy, substitutes the value, forwards the
// request, and redacts the response (threat model T-26 to T-30, T-44).
package proxy

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/subtle"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"secrethandoff.com/cli/internal/loopback"
	"secrethandoff.com/cli/internal/policy"
	"secrethandoff.com/cli/internal/secrets"
)

var secretRef = regexp.MustCompile(`\{\{secret:([A-Za-z][A-Za-z0-9_]{0,63})\}\}`)

const (
	maxRequestBody  = 8 << 20
	maxResponseBody = 16 << 20
)

// Proxy is the per-session HTTPS proxy.
type Proxy struct {
	store     *secrets.Store
	ln        net.Listener
	password  string
	dir       string
	transport http.RoundTripper

	mu sync.Mutex
	ca *authority
}

// Settings tell an agent how to route one command through the proxy. They
// hold no secret value. The proxy credential works only through the proxy.
type Settings struct {
	ProxyURL   string
	CACertFile string
	Hosts      []string
}

// Start listens on 127.0.0.1. transport forwards requests upstream; nil
// uses the default transport.
func Start(store *secrets.Store, transport http.RoundTripper) (*Proxy, error) {
	ln, err := loopback.Listen()
	if err != nil {
		return nil, err
	}
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		ln.Close()
		return nil, err
	}
	dir, err := os.MkdirTemp("", "secrethandoff-proxy-")
	if err != nil {
		ln.Close()
		return nil, err
	}
	if transport == nil {
		tr := http.DefaultTransport.(*http.Transport).Clone()
		tr.Proxy = nil
		transport = tr
	}
	p := &Proxy{store: store, ln: ln, password: base64.RawURLEncoding.EncodeToString(b), dir: dir, transport: transport}
	go p.serve()
	return p, nil
}

// Close stops the proxy and removes the CA certificate file.
func (p *Proxy) Close() error {
	err := p.ln.Close()
	os.RemoveAll(p.dir)
	return err
}

// Prepare creates or rotates the CA for the hosts of all ready secrets and
// writes its certificate. It returns the settings for agent commands.
func (p *Proxy) Prepare() (Settings, error) {
	var domains, hosts []string
	seen := map[string]bool{}
	for _, info := range p.store.List() {
		for _, d := range info.Policy.ConstraintDomains() {
			if !seen[d] {
				seen[d] = true
				domains = append(domains, d)
			}
		}
		hosts = append(hosts, info.Policy.Hosts...)
	}
	if len(domains) == 0 {
		return Settings{}, errors.New("no secret is ready; call request_secret first")
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.ca == nil || !sameSet(p.ca.domains, domains) {
		ca, err := newAuthority(domains)
		if err != nil {
			return Settings{}, err
		}
		p.ca = ca
	}
	file := filepath.Join(p.dir, "ca.pem")
	if err := os.WriteFile(file, p.ca.PEM(), 0o600); err != nil {
		return Settings{}, err
	}
	return Settings{
		ProxyURL:   "http://sh:" + p.password + "@" + p.ln.Addr().String(),
		CACertFile: file,
		Hosts:      hosts,
	}, nil
}

func sameSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	m := map[string]bool{}
	for _, x := range a {
		m[x] = true
	}
	for _, x := range b {
		if !m[x] {
			return false
		}
	}
	return true
}

func (p *Proxy) serve() {
	for {
		conn, err := p.ln.Accept()
		if err != nil {
			return
		}
		go p.handle(conn)
	}
}

func (p *Proxy) authorized(req *http.Request) bool {
	user, pass, ok := parseBasic(req.Header.Get("Proxy-Authorization"))
	return ok && user == "sh" && subtle.ConstantTimeCompare([]byte(pass), []byte(p.password)) == 1
}

func parseBasic(h string) (string, string, bool) {
	const prefix = "Basic "
	if !strings.HasPrefix(h, prefix) {
		return "", "", false
	}
	b, err := base64.StdEncoding.DecodeString(h[len(prefix):])
	if err != nil {
		return "", "", false
	}
	user, pass, ok := strings.Cut(string(b), ":")
	return user, pass, ok
}

func reply(conn net.Conn, status int, msg string) {
	fmt.Fprintf(conn, "HTTP/1.1 %d %s\r\nContent-Type: text/plain\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s", status, http.StatusText(status), len(msg), msg)
}

func (p *Proxy) handle(conn net.Conn) {
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(2 * time.Minute)) //nolint:errcheck
	br := bufio.NewReader(conn)
	req, err := http.ReadRequest(br)
	if err != nil {
		return
	}
	if !p.authorized(req) {
		reply(conn, http.StatusProxyAuthRequired, "secrethandoff proxy: missing or wrong proxy credential")
		return
	}
	if req.Method != http.MethodConnect {
		reply(conn, http.StatusMethodNotAllowed, "secrethandoff proxy: only https URLs are supported")
		return
	}
	host, port, err := net.SplitHostPort(req.Host)
	if err != nil {
		reply(conn, http.StatusBadRequest, "secrethandoff proxy: bad CONNECT target")
		return
	}
	if !p.hostInAnyPolicy(host, port) {
		reply(conn, http.StatusForbidden, "secrethandoff proxy: "+host+" is outside every secret's policy")
		return
	}
	p.mu.Lock()
	ca := p.ca
	p.mu.Unlock()
	if ca == nil {
		reply(conn, http.StatusServiceUnavailable, "secrethandoff proxy: call proxy_settings first")
		return
	}
	fmt.Fprint(conn, "HTTP/1.1 200 Connection Established\r\n\r\n")
	tlsConn := tls.Server(&bufferedConn{Conn: conn, r: br}, &tls.Config{
		MinVersion: tls.VersionTLS12,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			// The SNI must name the host of the CONNECT (threat model T-26).
			if !strings.EqualFold(hello.ServerName, host) {
				return nil, errors.New("SNI does not match the CONNECT host")
			}
			return ca.leaf(strings.ToLower(host))
		},
	})
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	defer tlsConn.Close()
	tr := bufio.NewReader(tlsConn)
	for {
		inner, err := http.ReadRequest(tr)
		if err != nil {
			return
		}
		resp := p.forward(inner, host, port)
		resp.Write(tlsConn) //nolint:errcheck
		resp.Body.Close()
		if inner.Close || resp.Close {
			return
		}
	}
}

type bufferedConn struct {
	net.Conn
	r *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.r.Read(p) }

func (p *Proxy) hostInAnyPolicy(host, port string) bool {
	for _, info := range p.store.List() {
		if info.Policy.AllowsHost(host, port) {
			return true
		}
	}
	return false
}

func errorResponse(req *http.Request, status int, msg string) *http.Response {
	return &http.Response{StatusCode: status, Status: strconv.Itoa(status) + " " + http.StatusText(status), Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: http.Header{"Content-Type": {"text/plain"}}, Body: io.NopCloser(strings.NewReader("secrethandoff proxy: " + msg)), ContentLength: int64(len("secrethandoff proxy: " + msg)), Request: req, Close: true}
}

// forward checks, substitutes, sends, and redacts one request.
func (p *Proxy) forward(req *http.Request, host, port string) *http.Response {
	reqHost, reqPort := req.Host, ""
	if h, pt, err := net.SplitHostPort(req.Host); err == nil {
		reqHost, reqPort = h, pt
	}
	if reqPort == "" {
		reqPort = "443"
	}
	if !strings.EqualFold(reqHost, host) || reqPort != port {
		return errorResponse(req, http.StatusMisdirectedRequest, "the Host header does not match the tunnel")
	}
	u := &url.URL{Scheme: "https", Host: req.Host, Path: req.URL.Path, RawPath: req.URL.RawPath, RawQuery: req.URL.RawQuery}
	if strings.Contains(u.Path, "{{secret:") {
		return errorResponse(req, http.StatusBadRequest, "{{secret:NAME}} may not appear in the path")
	}
	body, err := io.ReadAll(io.LimitReader(req.Body, maxRequestBody+1))
	if err != nil || len(body) > maxRequestBody {
		return errorResponse(req, http.StatusRequestEntityTooLarge, "request body too large")
	}

	names := map[string]bool{}
	collect := func(s string) {
		for _, m := range secretRef.FindAllStringSubmatch(s, -1) {
			names[m[1]] = true
		}
	}
	collect(u.RawQuery)
	collect(string(body))
	for k, vs := range req.Header {
		for _, v := range vs {
			if !strings.EqualFold(k, "Proxy-Authorization") {
				collect(v)
			}
		}
	}
	for name := range names {
		if err := p.store.Use(name, func(_ []byte, pol policy.Policy) error { return pol.Allows(req.Method, u) }); err != nil {
			return errorResponse(req, http.StatusForbidden, name+": "+err.Error())
		}
	}

	var missing error
	sub := func(s string, escape func(string) string) string {
		return secretRef.ReplaceAllStringFunc(s, func(ref string) string {
			var out string
			if err := p.store.Use(secretRef.FindStringSubmatch(ref)[1], func(v []byte, _ policy.Policy) error { out = escape(string(v)); return nil }); err != nil {
				missing = err
			}
			return out
		})
	}
	identity := func(s string) string { return s }
	out, err := http.NewRequest(req.Method, u.String(), nil)
	if err != nil {
		return errorResponse(req, http.StatusBadRequest, "bad request")
	}
	out.URL.RawQuery = sub(u.RawQuery, url.QueryEscape)
	for k, vs := range req.Header {
		// Drop Accept-Encoding so that the response is decompressed before
		// redaction: a compressed body would hide a reflected secret.
		if strings.EqualFold(k, "Proxy-Authorization") || strings.EqualFold(k, "Proxy-Connection") || strings.EqualFold(k, "Accept-Encoding") {
			continue
		}
		for _, v := range vs {
			out.Header.Add(k, sub(v, identity))
		}
	}
	newBody := []byte(sub(string(body), identity))
	out.Body, out.ContentLength = io.NopCloser(bytes.NewReader(newBody)), int64(len(newBody))
	if missing != nil {
		return errorResponse(req, http.StatusForbidden, missing.Error())
	}

	resp, err := p.transport.RoundTrip(out)
	if err != nil {
		return errorResponse(req, http.StatusBadGateway, "upstream request failed")
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody+1))
	if err != nil || len(respBody) > maxResponseBody {
		return errorResponse(req, http.StatusBadGateway, "response too large for the secrets proxy")
	}
	r := p.store.Redactor()
	respBody, _ = r.Bytes(respBody)
	header := http.Header{}
	for k, vs := range resp.Header {
		if strings.EqualFold(k, "Content-Length") || strings.EqualFold(k, "Transfer-Encoding") {
			continue
		}
		for _, v := range vs {
			red, _ := r.String(v)
			header.Add(k, red)
		}
	}
	return &http.Response{StatusCode: resp.StatusCode, Status: resp.Status, Proto: "HTTP/1.1", ProtoMajor: 1, ProtoMinor: 1,
		Header: header, Body: io.NopCloser(bytes.NewReader(respBody)), ContentLength: int64(len(respBody)), Request: req}
}
