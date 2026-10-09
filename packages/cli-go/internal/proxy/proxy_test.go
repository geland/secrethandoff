package proxy

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"secrethandoff.com/cli/internal/policy"
	"secrethandoff.com/cli/internal/secrets"
)

const value = "proxy-test-Value_9Lm2Qx7Rt4Wz8Np3"

type rig struct {
	t        *testing.T
	p        *Proxy
	settings Settings
	client   *http.Client
	got      chan *http.Request
}

func newRig(t *testing.T, pol policy.Policy) *rig {
	t.Helper()
	got := make(chan *http.Request, 10)
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got <- r.Clone(context.Background())
		w.Header().Set("X-Echo", r.Header.Get("Authorization"))
		if r.Header.Get("Accept-Encoding") == "gzip" {
			w.Header().Set("Content-Encoding", "gzip")
			gz := gzip.NewWriter(w)
			fmt.Fprintf(gz, "echo %s", r.Header.Get("Authorization"))
			gz.Close()
			return
		}
		fmt.Fprintf(w, "echo %s", r.Header.Get("Authorization"))
	}))
	t.Cleanup(upstream.Close)
	roots := x509.NewCertPool()
	roots.AddCert(upstream.Certificate())
	tr := &http.Transport{
		TLSClientConfig: &tls.Config{RootCAs: roots, ServerName: "example.com"},
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			return (&net.Dialer{}).DialContext(ctx, network, upstream.Listener.Addr().String())
		},
	}
	store := secrets.NewStore()
	pol, err := policy.Parse(pol)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Put("API_KEY", []byte(value), pol); err != nil {
		t.Fatal(err)
	}
	p, err := Start(store, tr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.Close() })
	s, err := p.Prepare()
	if err != nil {
		t.Fatal(err)
	}
	caPEM, err := os.ReadFile(s.CACertFile)
	if err != nil {
		t.Fatal(err)
	}
	pool := x509.NewCertPool()
	pool.AppendCertsFromPEM(caPEM)
	proxyURL, _ := url.Parse(s.ProxyURL)
	client := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxyURL), TLSClientConfig: &tls.Config{RootCAs: pool}, DisableCompression: true}}
	return &rig{t: t, p: p, settings: s, client: client, got: got}
}

func (r *rig) do(method, rawURL string, header map[string]string) (int, string, http.Header) {
	r.t.Helper()
	req, _ := http.NewRequest(method, rawURL, nil)
	for k, v := range header {
		req.Header.Set(k, v)
	}
	res, err := r.client.Do(req)
	if err != nil {
		return 0, err.Error(), nil
	}
	defer res.Body.Close()
	b, _ := io.ReadAll(res.Body)
	return res.StatusCode, string(b), res.Header
}

func TestSubstitutesAndRedacts(t *testing.T) {
	r := newRig(t, policy.Policy{Hosts: []string{"example.com"}, Methods: []string{"GET"}, Paths: []string{"/v1/*"}})
	code, body, hdr := r.do("GET", "https://example.com/v1/items?k={{secret:API_KEY}}", map[string]string{"Authorization": "Bearer {{secret:API_KEY}}"})
	if code != 200 {
		t.Fatalf("status %d: %s", code, body)
	}
	up := <-r.got
	if up.Header.Get("Authorization") != "Bearer "+value || up.URL.Query().Get("k") != value {
		t.Fatal("the upstream did not receive the value")
	}
	if strings.Contains(body, value) || strings.Contains(hdr.Get("X-Echo"), value) || !strings.Contains(body, "[REDACTED:API_KEY]") {
		t.Fatalf("the reflected value was not redacted: %q %q", body, hdr.Get("X-Echo"))
	}
	if up.Header.Get("Proxy-Authorization") != "" {
		t.Fatal("the proxy credential went upstream")
	}
	// A client that asks for gzip still gets a redacted, decompressed body.
	code, body, _ = r.do("GET", "https://example.com/v1/gz", map[string]string{"Authorization": "Bearer {{secret:API_KEY}}", "Accept-Encoding": "gzip"})
	if code != 200 || strings.Contains(body, value) || !strings.Contains(body, "[REDACTED:API_KEY]") {
		t.Fatalf("gzip: %d %q", code, body)
	}
}

func TestPolicyChecks(t *testing.T) {
	r := newRig(t, policy.Policy{Hosts: []string{"example.com"}, Methods: []string{"GET"}, Paths: []string{"/v1/*"}})
	if code, _, _ := r.do("POST", "https://example.com/v1/items", map[string]string{"Authorization": "Bearer {{secret:API_KEY}}"}); code != http.StatusForbidden {
		t.Errorf("method outside policy: %d", code)
	}
	if code, _, _ := r.do("GET", "https://example.com/admin", map[string]string{"Authorization": "Bearer {{secret:API_KEY}}"}); code != http.StatusForbidden {
		t.Errorf("path outside policy: %d", code)
	}
	if code, _, _ := r.do("GET", "https://example.com/v1/{{secret:API_KEY}}", nil); code == 200 {
		t.Error("a reference in the path was accepted")
	}
	if _, msg, _ := r.do("GET", "https://other.example.org/", map[string]string{"Authorization": "Bearer {{secret:API_KEY}}"}); !strings.Contains(msg, "Forbidden") && !strings.Contains(msg, "403") {
		t.Errorf("a host outside every policy was tunneled: %s", msg)
	}
}

func TestProxyCredentialRequired(t *testing.T) {
	r := newRig(t, policy.Policy{Hosts: []string{"example.com"}})
	proxyURL, _ := url.Parse(r.settings.ProxyURL)
	proxyURL.User = url.UserPassword("sh", "wrong")
	r.client.Transport.(*http.Transport).Proxy = http.ProxyURL(proxyURL)
	if _, msg, _ := r.do("GET", "https://example.com/", nil); !strings.Contains(msg, "Proxy Authentication Required") && !strings.Contains(msg, "407") {
		t.Fatalf("wrong credential accepted: %s", msg)
	}
}

func TestHostHeaderMustMatchTunnel(t *testing.T) {
	r := newRig(t, policy.Policy{Hosts: []string{"example.com", "example.org"}})
	req, _ := http.NewRequest("GET", "https://example.com/", nil)
	req.Host = "example.org"
	req.Header.Set("Authorization", "Bearer {{secret:API_KEY}}")
	res, err := r.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	res.Body.Close()
	if res.StatusCode != http.StatusMisdirectedRequest {
		t.Fatalf("status %d", res.StatusCode)
	}
}

// TestCANameConstraints covers threat model T-29: the session CA can only
// vouch for the policy hosts.
func TestCANameConstraints(t *testing.T) {
	r := newRig(t, policy.Policy{Hosts: []string{"example.com"}})
	r.p.mu.Lock()
	ca := r.p.ca
	r.p.mu.Unlock()
	if !ca.cert.PermittedDNSDomainsCritical || len(ca.cert.PermittedDNSDomains) != 1 || ca.cert.PermittedDNSDomains[0] != "example.com" {
		t.Fatalf("constraints = %v", ca.cert.PermittedDNSDomains)
	}
	evil, err := ca.leaf("evil.test")
	if err != nil {
		t.Fatal(err)
	}
	leaf, _ := x509.ParseCertificate(evil.Certificate[0])
	roots := x509.NewCertPool()
	roots.AddCert(ca.cert)
	if _, err := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: "evil.test"}); err == nil {
		t.Fatal("a leaf outside the name constraints verified")
	}
	block, _ := pem.Decode(ca.PEM())
	if block == nil || block.Type != "CERTIFICATE" || bytes.Contains(ca.PEM(), []byte("PRIVATE")) {
		t.Fatal("the CA file must hold only the certificate")
	}
}
