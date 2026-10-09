package main

import (
	"encoding/json"
	"net/url"
	"testing"

	"secrethandoff.com/cli/internal/policy"
	"secrethandoff.com/cli/internal/secrets"
)

// A password with characters that break a form or JSON body when written raw.
const awkward = `p&ss=w+rd "q" \ <x>`

func TestBodyEscapeFollowsContentType(t *testing.T) {
	form := bodyEscape(map[string]string{"content-type": "application/x-www-form-urlencoded; charset=utf-8"})(awkward)
	if v, err := url.ParseQuery("password=" + form); err != nil || v.Get("password") != awkward {
		t.Fatalf("form: %q decodes to %q (%v)", form, v.Get("password"), err)
	}
	for _, ct := range []string{"application/json", "application/vnd.api+json"} {
		body := `{"password":"` + bodyEscape(map[string]string{"Content-Type": ct})(awkward) + `"}`
		var got struct{ Password string }
		if err := json.Unmarshal([]byte(body), &got); err != nil || got.Password != awkward {
			t.Fatalf("%s: %s decodes to %q (%v)", ct, body, got.Password, err)
		}
	}
	if raw := bodyEscape(map[string]string{"Content-Type": "text/plain"})(awkward); raw != awkward {
		t.Fatalf("text/plain changed the value: %q", raw)
	}
	if raw := bodyEscape(nil)(awkward); raw != awkward {
		t.Fatalf("no Content-Type changed the value: %q", raw)
	}
}

func TestRedactorRemovesJSONEscapedValue(t *testing.T) {
	store := secrets.NewStore()
	if err := store.Put("PASS", []byte(awkward), policy.Policy{Hosts: []string{"api.example.com"}}); err != nil {
		t.Fatal(err)
	}
	out, n := store.Redactor().String(`{"echo":"` + secrets.JSONEscape(awkward) + `"}`)
	if n == 0 || out != `{"echo":"[REDACTED:PASS]"}` {
		t.Fatalf("redacted %d: %s", n, out)
	}
}
