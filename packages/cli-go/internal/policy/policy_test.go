package policy

import (
	"net/url"
	"testing"
)

func mustParse(t *testing.T, p Policy) Policy {
	t.Helper()
	out, err := Parse(p)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestParseRejects(t *testing.T) {
	bad := []Policy{
		{},
		{Hosts: []string{"localhost"}},
		{Hosts: []string{"10.0.0.1"}},
		{Hosts: []string{"[::1]"}},
		{Hosts: []string{"*.com"}},
		{Hosts: []string{"api.*.com"}},
		{Hosts: []string{"bad_host.example.com"}},
		{Hosts: []string{"api.example.com:"}},
		{Hosts: []string{"api.example.com"}, Methods: []string{"CONNECT"}},
		{Hosts: []string{"api.example.com"}, Paths: []string{"v1/x"}},
		{Hosts: []string{"api.example.com"}, Paths: []string{"/v1?x=1"}},
		{Hosts: []string{"api.example.com"}, Paths: []string{"/v1/["}},
	}
	for _, p := range bad {
		if _, err := Parse(p); err == nil {
			t.Errorf("Parse(%+v) accepted an invalid policy", p)
		}
	}
}

func TestCanonicalForm(t *testing.T) {
	p := mustParse(t, Policy{Hosts: []string{"API.Example.com", "api.example.com"}, Methods: []string{"post", "get"}})
	if len(p.Hosts) != 1 || p.Hosts[0] != "api.example.com" || p.Methods[0] != "GET" || p.Methods[1] != "POST" {
		t.Fatalf("canonical form = %+v", p)
	}
	q := mustParse(t, Policy{Hosts: []string{"api.example.com"}, Methods: []string{"GET", "POST"}})
	if p.Hash() != q.Hash() {
		t.Fatal("equal policies must have equal hashes")
	}
}

func TestAllows(t *testing.T) {
	p := mustParse(t, Policy{Hosts: []string{"api.stripe.com", "*.example.com", "files.example.org:8443"}, Methods: []string{"GET", "POST"}, Paths: []string{"/v1/charges", "/v1/customers/*"}})
	cases := []struct {
		method, raw string
		ok          bool
	}{
		{"GET", "https://api.stripe.com/v1/charges", true},
		{"post", "https://api.stripe.com:443/v1/customers/cus_123", true},
		{"GET", "https://a.example.com/v1/charges", true},
		{"GET", "https://files.example.org:8443/v1/charges", true},
		{"GET", "http://api.stripe.com/v1/charges", false},
		{"DELETE", "https://api.stripe.com/v1/charges", false},
		{"GET", "https://api.stripe.com/v1/refunds", false},
		{"GET", "https://api.stripe.com/v1/customers/cus_1/sources", false},
		{"GET", "https://api.stripe.com.evil.test/v1/charges", false},
		{"GET", "https://evilapi.stripe.com/v1/charges", false},
		{"GET", "https://example.com/v1/charges", false},
		{"GET", "https://xexample.com/v1/charges", false},
		{"GET", "https://a.b.example.com/v1/charges", false},
		{"GET", "https://files.example.org/v1/charges", false},
		{"GET", "https://api.stripe.com:8443/v1/charges", false},
		{"GET", "https://user:pw@api.stripe.com/v1/charges", false},
		{"GET", "https://api.stripe.com/v1/customers/../charges", false},
		{"GET", "https://api.stripe.com/v1/customers/%2e%2e", false},
	}
	for _, c := range cases {
		u, err := url.Parse(c.raw)
		if err != nil {
			t.Fatal(err)
		}
		if err := p.Allows(c.method, u); (err == nil) != c.ok {
			t.Errorf("Allows(%s %s) = %v, want ok=%v", c.method, c.raw, err, c.ok)
		}
	}
}

func TestAnyPathAndDescribe(t *testing.T) {
	p := mustParse(t, Policy{Hosts: []string{"api.example.com"}})
	u, _ := url.Parse("https://api.example.com/anything/here?q=1")
	if err := p.Allows("PATCH", u); err != nil {
		t.Fatal(err)
	}
	if got := p.Describe(); got != "Sent only to api.example.com, on any path." {
		t.Fatalf("Describe = %q", got)
	}
	if p.HasWildcard() || !mustParse(t, Policy{Hosts: []string{"*.example.com"}}).HasWildcard() {
		t.Fatal("HasWildcard is wrong")
	}
}
