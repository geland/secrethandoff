package secrets

import (
	"encoding/base64"
	"encoding/hex"
	"net/url"
	"strings"
	"testing"

	"secrethandoff.com/cli/internal/policy"
)

const testValue = "sk_test_51Hx9ZqLkJv8Q2wE7rT5yU3iO1pA0sD"

func newStoreWith(t *testing.T) *Store {
	t.Helper()
	p, err := policy.Parse(policy.Policy{Hosts: []string{"api.example.com"}})
	if err != nil {
		t.Fatal(err)
	}
	s := NewStore()
	if err := s.Put("STRIPE_KEY", []byte(testValue), p); err != nil {
		t.Fatal(err)
	}
	return s
}

func TestStoreNeverListsValues(t *testing.T) {
	s := newStoreWith(t)
	for _, info := range s.List() {
		if strings.Contains(info.Name+info.Policy.Describe(), testValue) {
			t.Fatal("List exposed a value")
		}
	}
	if !s.Has("STRIPE_KEY") || s.Has("OTHER") {
		t.Fatal("Has is wrong")
	}
	if err := s.Put("bad name", []byte("x"), policy.Policy{}); err == nil {
		t.Fatal("accepted an invalid name")
	}
}

func TestForgetWipesValue(t *testing.T) {
	s := newStoreWith(t)
	var held []byte
	_ = s.Use("STRIPE_KEY", func(v []byte, _ policy.Policy) error { held = v; return nil })
	if !s.Forget("STRIPE_KEY") || s.Has("STRIPE_KEY") {
		t.Fatal("Forget failed")
	}
	for _, b := range held {
		if b != 0 {
			t.Fatal("Forget did not wipe the stored value")
		}
	}
	if err := s.Use("STRIPE_KEY", func([]byte, policy.Policy) error { return nil }); err == nil {
		t.Fatal("Use after Forget succeeded")
	}
}

func TestRedactsEveryEncoding(t *testing.T) {
	r := newStoreWith(t).Redactor()
	basic := base64.StdEncoding.EncodeToString([]byte("user:" + testValue))
	inputs := map[string]string{
		"raw":        "token=" + testValue + "&x=1",
		"hex":        "h:" + hex.EncodeToString([]byte(testValue)),
		"HEX":        "h:" + strings.ToUpper(hex.EncodeToString([]byte(testValue))),
		"query":      url.QueryEscape(testValue),
		"base64":     base64.StdEncoding.EncodeToString([]byte(testValue)),
		"base64url":  base64.RawURLEncoding.EncodeToString([]byte(testValue)),
		"basic-auth": "Authorization: Basic " + basic,
		"offset-1":   base64.StdEncoding.EncodeToString([]byte("a" + testValue + "z")),
		"offset-2":   base64.StdEncoding.EncodeToString([]byte("ab" + testValue + "yz")),
	}
	for label, in := range inputs {
		out, n := r.String(in)
		if n == 0 || leaks(out) {
			t.Errorf("%s: not redacted: %q", label, out)
		}
		if !strings.Contains(out, "[REDACTED:STRIPE_KEY]") {
			t.Errorf("%s: missing marker: %q", label, out)
		}
	}
	if out, n := r.String("nothing secret here"); n != 0 || out != "nothing secret here" {
		t.Fatal("redacted text without a secret")
	}
}

// leaks reports whether any recognizable encoding of testValue remains.
func leaks(s string) bool {
	if strings.Contains(s, testValue) || strings.Contains(strings.ToLower(s), hex.EncodeToString([]byte(testValue))) {
		return true
	}
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.RawURLEncoding} {
		for _, core := range base64Cores(enc, []byte(testValue)) {
			if strings.Contains(s, core) {
				return true
			}
		}
	}
	return false
}
