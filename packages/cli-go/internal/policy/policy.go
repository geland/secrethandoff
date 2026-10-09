// Package policy parses and enforces the use policy that a human approves for
// one secret: the hosts, methods, and paths that may receive it (ADR 0009).
package policy

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path"
	"sort"
	"strings"
)

// Policy is immutable after Parse. The binary enforces the policy that the
// human saw at fill time (threat model T-05).
type Policy struct {
	Hosts   []string `json:"hosts"`
	Methods []string `json:"methods,omitempty"`
	Paths   []string `json:"paths,omitempty"`
}

var allowedMethods = map[string]bool{"GET": true, "HEAD": true, "POST": true, "PUT": true, "PATCH": true, "DELETE": true, "OPTIONS": true}

const (
	maxHosts = 10
	maxPaths = 20
)

// Parse validates a policy and returns its canonical form: lowercase hosts,
// uppercase methods, sorted and without duplicates.
func Parse(p Policy) (Policy, error) {
	if len(p.Hosts) == 0 {
		return Policy{}, errors.New("policy needs at least one host")
	}
	if len(p.Hosts) > maxHosts || len(p.Paths) > maxPaths {
		return Policy{}, fmt.Errorf("policy allows at most %d hosts and %d paths", maxHosts, maxPaths)
	}
	out := Policy{}
	for _, h := range p.Hosts {
		h = strings.ToLower(strings.TrimSpace(h))
		if err := validHost(h); err != nil {
			return Policy{}, err
		}
		out.Hosts = append(out.Hosts, h)
	}
	for _, m := range p.Methods {
		m = strings.ToUpper(strings.TrimSpace(m))
		if !allowedMethods[m] {
			return Policy{}, fmt.Errorf("method %q is not allowed", m)
		}
		out.Methods = append(out.Methods, m)
	}
	for _, pt := range p.Paths {
		if !strings.HasPrefix(pt, "/") || strings.ContainsAny(pt, "?#\\") {
			return Policy{}, fmt.Errorf("path %q must start with / and contain no query or fragment", pt)
		}
		if _, err := path.Match(pt, "/"); err != nil {
			return Policy{}, fmt.Errorf("path %q is not a valid pattern", pt)
		}
		out.Paths = append(out.Paths, pt)
	}
	out.Hosts, out.Methods, out.Paths = uniq(out.Hosts), uniq(out.Methods), uniq(out.Paths)
	return out, nil
}

// validHost accepts a DNS name with an optional port, or a wildcard in the
// first label only ("*.example.com"). IP literals are refused: a credential
// must go to a named host that TLS can verify.
func validHost(h string) error {
	name, port := h, ""
	if i := strings.LastIndex(h, ":"); i >= 0 {
		name, port = h[:i], h[i+1:]
		if port == "" || len(port) > 5 || strings.Trim(port, "0123456789") != "" {
			return fmt.Errorf("host %q has an invalid port", h)
		}
	}
	if net.ParseIP(strings.Trim(name, "[]")) != nil {
		return fmt.Errorf("host %q is an IP address; use a host name", h)
	}
	labels := strings.Split(strings.TrimPrefix(name, "*."), ".")
	if strings.HasPrefix(name, "*.") && len(labels) < 2 {
		return fmt.Errorf("wildcard host %q must have at least two labels after *", h)
	}
	if len(labels) < 2 {
		return fmt.Errorf("host %q must be a full domain name", h)
	}
	for _, l := range labels {
		if l == "" || len(l) > 63 || strings.Trim(l, "abcdefghijklmnopqrstuvwxyz0123456789-") != "" || strings.HasPrefix(l, "-") || strings.HasSuffix(l, "-") {
			return fmt.Errorf("host %q is not a valid domain name", h)
		}
	}
	return nil
}

func uniq(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	sort.Strings(in)
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}

// HasWildcard reports whether any host is a wildcard. The fill page warns
// about it.
func (p Policy) HasWildcard() bool {
	for _, h := range p.Hosts {
		if strings.HasPrefix(h, "*.") {
			return true
		}
	}
	return false
}

// Allows reports whether the policy permits sending the secret with this
// request. Only HTTPS is allowed.
func (p Policy) Allows(method string, u *url.URL) error {
	if u.Scheme != "https" {
		return errors.New("secrets are sent only over https")
	}
	if u.User != nil {
		return errors.New("URLs with user information are not allowed")
	}
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if port == "443" {
		port = ""
	}
	if !p.hostAllowed(host, port) {
		return fmt.Errorf("host %q is outside this secret's policy", u.Host)
	}
	if len(p.Methods) > 0 && !contains(p.Methods, strings.ToUpper(method)) {
		return fmt.Errorf("method %s is outside this secret's policy", strings.ToUpper(method))
	}
	if len(p.Paths) > 0 {
		reqPath := u.EscapedPath()
		if reqPath == "" {
			reqPath = "/"
		}
		if !p.pathAllowed(reqPath) {
			return fmt.Errorf("path %q is outside this secret's policy", reqPath)
		}
	}
	return nil
}

// AllowsHost reports whether host (and port, "" for 443) is one of the
// policy's hosts. The proxy uses it to decide which tunnels it may open.
func (p Policy) AllowsHost(host, port string) bool {
	if port == "443" {
		port = ""
	}
	return p.hostAllowed(strings.ToLower(host), port)
}

// ConstraintDomains returns the DNS names for X.509 name constraints: the
// exact hosts, and the parent domain of each wildcard host.
func (p Policy) ConstraintDomains() []string {
	var out []string
	for _, h := range p.Hosts {
		name := h
		if i := strings.LastIndex(h, ":"); i >= 0 {
			name = h[:i]
		}
		out = append(out, strings.TrimPrefix(name, "*."))
	}
	return out
}

func (p Policy) hostAllowed(host, port string) bool {
	for _, h := range p.Hosts {
		name, want := h, ""
		if i := strings.LastIndex(h, ":"); i >= 0 {
			name, want = h[:i], h[i+1:]
		}
		if want == "443" {
			want = ""
		}
		if want != port {
			continue
		}
		if name == host {
			return true
		}
		// A wildcard matches exactly one extra label: *.example.com matches
		// a.example.com but not example.com or a.b.example.com.
		if suffix := name[1:]; strings.HasPrefix(name, "*.") && strings.HasSuffix(host, suffix) {
			if label := strings.TrimSuffix(host, suffix); label != "" && !strings.Contains(label, ".") {
				return true
			}
		}
	}
	return false
}

func (p Policy) pathAllowed(reqPath string) bool {
	if strings.Contains(reqPath, "/../") || strings.HasSuffix(reqPath, "/..") || strings.Contains(strings.ToLower(reqPath), "%2e%2e") {
		return false
	}
	for _, pt := range p.Paths {
		if ok, _ := path.Match(pt, reqPath); ok {
			return true
		}
	}
	return false
}

func contains(list []string, s string) bool {
	for _, x := range list {
		if x == s {
			return true
		}
	}
	return false
}

// Hash is a stable digest of the canonical policy. The relay binds it into
// the ciphertext (threat model T-05).
func (p Policy) Hash() string {
	b, _ := json.Marshal(p)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Describe returns the policy as plain text for the fill page.
func (p Policy) Describe() string {
	var b strings.Builder
	b.WriteString("Sent only to " + strings.Join(p.Hosts, ", "))
	if len(p.Methods) > 0 {
		b.WriteString(", with methods " + strings.Join(p.Methods, ", "))
	}
	if len(p.Paths) > 0 {
		b.WriteString(", on paths " + strings.Join(p.Paths, ", "))
	} else {
		b.WriteString(", on any path")
	}
	b.WriteString(".")
	return b.String()
}
