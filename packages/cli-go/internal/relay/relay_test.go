package relay

import (
	"crypto/ecdh"
	"crypto/hpke"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestSealOpenAndBinding(t *testing.T) {
	r, err := New(`{"hosts":["api.example.com"]}`, 10*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	r.ID = "AAAAAAAAAAAAAAAAAAAAAA"
	pk, err := hpke.DHKEM(ecdh.P256()).NewPublicKey(r.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	ct, err := hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), Info(r.ID, r.PolicyHash, r.Expires), []byte("s3cret"))
	if err != nil {
		t.Fatal(err)
	}
	if pt, err := r.Open(ct); err != nil || string(pt) != "s3cret" {
		t.Fatalf("open: %v", err)
	}
	// A ciphertext bound to another request, policy, or expiry fails.
	for _, info := range [][]byte{Info("BBBBBBBBBBBBBBBBBBBBBB", r.PolicyHash, r.Expires), Info(r.ID, "x", r.Expires), Info(r.ID, r.PolicyHash, r.Expires+1)} {
		other, _ := hpke.Seal(pk, hpke.HKDFSHA256(), hpke.AES256GCM(), info, []byte("s3cret"))
		if _, err := r.Open(other); err == nil {
			t.Fatal("a moved ciphertext decrypted")
		}
	}
	if _, err := New("{}", 2*time.Hour); err == nil {
		t.Fatal("accepted a lifetime over one hour")
	}
}

func TestLinkNeverHoldsPickupToken(t *testing.T) {
	r, _ := New(`{"hosts":["api.example.com"]}`, time.Minute)
	r.ID = "AAAAAAAAAAAAAAAAAAAAAA"
	link := r.Link("https://secrethandoff.com")
	if strings.Contains(link, r.pickupToken) || !strings.HasPrefix(link, "https://secrethandoff.com/q/AAAAAAAAAAAAAAAAAAAAAA#v1.") {
		t.Fatalf("link = %s", link)
	}
	if parts := strings.Split(strings.SplitN(link, "#", 2)[1], "."); len(parts) != 4 || len(parts[1]) != 87 || len(parts[2]) != 43 || len(parts[3]) != 43 {
		t.Fatalf("fragment layout: %v", parts)
	}
}

func TestPowAndPairing(t *testing.T) {
	in := powInput("a", "b", "c", "d", 1)
	nonce := SolvePow(in)
	if LeadingZeroBits(sha256.Sum256([]byte(in+nonce))) < PowBits {
		t.Fatal("bad proof of work")
	}
	code := PairingCode(make([]byte, 65))
	if len(code) != 15 || code[5] != '-' || code[10] != '-' || code == PairingCode(append(make([]byte, 64), 1)) {
		t.Fatalf("pairing code %q", code)
	}
	if _, err := NewClient("http://relay.example.com"); err == nil {
		t.Fatal("accepted a plain http relay")
	}
	if _, err := NewClient("http://127.0.0.1:8787"); err != nil {
		t.Fatal("refused a loopback test relay")
	}
}

// TestBrowserInterop seals with the page's code (app/lib/sealed.ts) and
// opens with Go's crypto/hpke, and compares the pairing codes and fill
// proofs. It needs Node.js 22.18 or newer.
func TestBrowserInterop(t *testing.T) {
	skip := t.Skipf
	if os.Getenv("CI") != "" {
		// In CI the browser-to-Go check is a release gate (GG-10).
		skip = t.Fatalf
	}
	node, err := exec.LookPath("node")
	if err != nil {
		skip("node not found")
	}
	_, file, _, _ := runtime.Caller(0)
	repo := filepath.Join(filepath.Dir(file), "..", "..", "..", "..")
	script := filepath.Join(t.TempDir(), "interop.mjs")
	sealed := filepath.Join(repo, "app", "lib", "sealed.ts")
	if _, err := os.Stat(sealed); err != nil {
		skip("app/lib/sealed.ts not found")
	}
	os.WriteFile(script, []byte(`
import { seal, sealedInfo, pairingCode, fillProof, confirmationCode, fromBase64Url, toBase64Url } from "`+filepath.ToSlash(sealed)+`";
const [pk, id, policyHash, expires, fill] = process.argv.slice(2);
const ct = await seal({ recipientPublicKey: fromBase64Url(pk), info: sealedInfo(id, policyHash, Number(expires)), plaintext: new TextEncoder().encode("from the browser") });
console.log(toBase64Url(ct));
console.log(await pairingCode(fromBase64Url(pk)));
console.log(toBase64Url(await fillProof(fromBase64Url(fill))));
console.log(await confirmationCode(id, ct));
`), 0o600)
	r, _ := New(`{"hosts":["api.example.com"]}`, time.Minute)
	r.ID = "CCCCCCCCCCCCCCCCCCCCCC"
	out, err := exec.Command(node, script, b64.EncodeToString(r.publicKey), r.ID, r.PolicyHash, strconv.FormatInt(r.Expires, 10), b64.EncodeToString(r.fillSecret)).CombinedOutput()
	if err != nil {
		skip("node could not run the TypeScript module (needs Node 22.18 or newer): %s", out)
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	ct, _ := b64.DecodeString(lines[0])
	if pt, err := r.Open(ct); err != nil || string(pt) != "from the browser" {
		t.Fatalf("Go could not open the browser ciphertext: %v", err)
	}
	if lines[1] != PairingCode(r.publicKey) {
		t.Fatalf("pairing codes differ: browser %s, Go %s", lines[1], PairingCode(r.publicKey))
	}
	proof, _ := FillProof(r.fillSecret)
	if lines[2] != b64.EncodeToString(proof) {
		t.Fatal("fill proofs differ")
	}
	if lines[3] != ConfirmationCode(r.ID, ct) {
		t.Fatalf("confirmation codes differ: browser %s, Go %s", lines[3], ConfirmationCode(r.ID, ct))
	}
	t.Logf("interop ok, ciphertext %d bytes, sha %s", len(ct), hex.EncodeToString(proof[:4]))
}

func TestUnsafeText(t *testing.T) {
	for _, s := range []string{"a\x1b[8mb", "a‮b", "a​b", "a\x00b", "a\rb", "a\u0085b"} {
		if !HasUnsafeText(s) || HasUnsafeText(CleanText(s)) {
			t.Errorf("%q not handled", s)
		}
	}
	if HasUnsafeText("Deploy needs the key.\nThanks — ok") {
		t.Fatal("plain text with a newline was rejected")
	}
}

// TestFixedVectors checks Go against testdata/sealed-vectors.json, which
// the browser code (app/lib/sealed.ts) produced with a fixed ephemeral key.
// tests/sealed.test.mjs checks the browser against the same file, so the
// two sides stay in step without Node in the Go tests (gate GG-10).
func TestFixedVectors(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "sealed-vectors.json"))
	if err != nil {
		t.Fatal(err)
	}
	var v struct {
		SkR, PkR, ID, PolicyHash, Plaintext, FillSecret, Ciphertext, PairingCode, FillProof, ConfirmationCode string
		Expires                                                                                               int64
	}
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatal(err)
	}
	unhex := func(s string) []byte { b, _ := hex.DecodeString(s); return b }
	kem, _, _ := suite()
	key, err := kem.NewPrivateKey(unhex(v.SkR))
	if err != nil {
		t.Fatal(err)
	}
	r := &Request{ID: v.ID, PolicyHash: v.PolicyHash, Expires: v.Expires, key: key, publicKey: unhex(v.PkR)}
	ct := unhex(v.Ciphertext)
	if pt, err := r.Open(ct); err != nil || string(pt) != v.Plaintext {
		t.Fatalf("Go could not open the browser vector: %v", err)
	}
	if got := PairingCode(unhex(v.PkR)); got != v.PairingCode {
		t.Fatalf("pairing code %s, want %s", got, v.PairingCode)
	}
	if proof, _ := FillProof(unhex(v.FillSecret)); b64.EncodeToString(proof) != v.FillProof {
		t.Fatal("fill proof differs from the vector")
	}
	if got := ConfirmationCode(v.ID, ct); got != v.ConfirmationCode {
		t.Fatalf("confirmation code %s, want %s", got, v.ConfirmationCode)
	}
}
