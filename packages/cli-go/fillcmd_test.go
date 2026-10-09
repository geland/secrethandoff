package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"secrethandoff.com/cli/internal/relay"
)

func TestFillCommand(t *testing.T) {
	r, err := relay.New(`{"hosts":["api.example.com"]}`, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	r.ID = "FILLFILLFILLFILLFILL01"
	var got struct{ Ciphertext, FillProof, Pow string }
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		switch {
		case req.Method == "GET":
			json.NewEncoder(w).Encode(relay.View{Reason: "Terminal test", Policy: r.PolicyJSON, State: "pending", ExpiresAt: r.Expires})
		case strings.HasSuffix(req.URL.Path, "/fill"):
			json.NewDecoder(req.Body).Decode(&got)
			sum := sha256.Sum256([]byte(got.Ciphertext))
			in := "v1fill|" + r.ID + "|" + base64.RawURLEncoding.EncodeToString(sum[:]) + "|" + got.Pow
			if relay.LeadingZeroBits(sha256.Sum256([]byte(in))) < relay.PowBits {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			json.NewEncoder(w).Encode(map[string]string{"state": "filled"})
		}
	}))
	defer srv.Close()
	link := r.Link(srv.URL)
	code := relay.PairingCode(r.PublicKey())

	var out, errOut bytes.Buffer
	if rc := runFill([]string{"--stdin", "--code", "WRONG-CODE0", link}, strings.NewReader("value"), &out, &errOut); rc == 0 {
		t.Fatal("accepted a wrong pairing code")
	}
	out.Reset()
	errOut.Reset()
	if rc := runFill([]string{"--stdin", "--code", code, link}, strings.NewReader("terminal-secret-77\n"), &out, &errOut); rc != 0 {
		t.Fatalf("fill failed: %s %s", out.String(), errOut.String())
	}
	if strings.Contains(out.String()+errOut.String(), "terminal-secret-77") || !strings.Contains(out.String(), code) {
		t.Fatalf("output: %s", out.String())
	}
	ct, _ := base64.RawURLEncoding.DecodeString(got.Ciphertext)
	if pt, err := r.Open(ct); err != nil || string(pt) != "terminal-secret-77" {
		t.Fatalf("the binary could not open the terminal fill: %v", err)
	}
	if rc := runFill([]string{"--stdin", "--code", code, strings.SplitN(link, "#", 2)[0]}, strings.NewReader("x"), &out, &errOut); rc == 0 {
		t.Fatal("accepted a link without its fragment")
	}
}

func TestFillCommandCleansRequesterText(t *testing.T) {
	r, _ := relay.New(`{"hosts":["api.example.com"]}`, 10*time.Minute)
	r.ID = "FILLFILLFILLFILLFILL02"
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == "GET" {
			json.NewEncoder(w).Encode(relay.View{Reason: "ok\x1b[8m hidden ‮", Policy: r.PolicyJSON, State: "pending", ExpiresAt: r.Expires})
			return
		}
		json.NewEncoder(w).Encode(map[string]string{"state": "filled"})
	}))
	defer srv.Close()
	var out, errOut bytes.Buffer
	runFill([]string{"--stdin", "--code", relay.PairingCode(r.PublicKey()), r.Link(srv.URL)}, strings.NewReader("v"), &out, &errOut)
	if strings.ContainsAny(out.String(), "\x1b‮") {
		t.Fatalf("control characters reached the terminal: %q", out.String())
	}
}
