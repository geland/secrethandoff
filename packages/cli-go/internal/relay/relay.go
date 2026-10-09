// Package relay is the binary's side of sealed requests through the relay
// service (ADR 0010): key pair, link, pairing code, fill proof, proof of
// work, creation, pickup, and decryption.
package relay

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/hpke"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/bits"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	// PowBits is the proof-of-work difficulty for request creation.
	PowBits = 18
	// MaxLifetime bounds a request's lifetime (threat model T-19).
	MaxLifetime = time.Hour
)

var b64 = base64.RawURLEncoding

func suite() (hpke.KEM, hpke.KDF, hpke.AEAD) {
	return hpke.DHKEM(ecdh.P256()), hpke.HKDFSHA256(), hpke.AES256GCM()
}

// Request is one sealed request. Its private key and pickup token stay in
// memory only and never appear in a link, a tool result, or a log.
type Request struct {
	ID         string
	PolicyJSON string
	PolicyHash string
	Expires    int64

	key         hpke.PrivateKey
	publicKey   []byte
	fillSecret  []byte
	pickupToken string
}

// New creates a request's keys and capabilities. It does not contact the
// service.
func New(policyJSON string, lifetime time.Duration) (*Request, error) {
	if lifetime <= 0 || lifetime > MaxLifetime {
		return nil, fmt.Errorf("lifetime must be at most %s", MaxLifetime)
	}
	kem, _, _ := suite()
	key, err := kem.GenerateKey()
	if err != nil {
		return nil, err
	}
	fill := make([]byte, 32)
	pickup := make([]byte, 32)
	if _, err := rand.Read(fill); err != nil {
		return nil, err
	}
	if _, err := rand.Read(pickup); err != nil {
		return nil, err
	}
	sum := sha256.Sum256([]byte(policyJSON))
	return &Request{
		PolicyJSON:  policyJSON,
		PolicyHash:  b64.EncodeToString(sum[:]),
		Expires:     time.Now().Add(lifetime).Unix(),
		key:         key,
		publicKey:   key.PublicKey().Bytes(),
		fillSecret:  fill,
		pickupToken: b64.EncodeToString(pickup),
	}, nil
}

// PublicKey returns the serialized public key (65 bytes for P-256).
func (r *Request) PublicKey() []byte { return append([]byte(nil), r.publicKey...) }

// Info is the HPKE info string that binds a ciphertext to this request.
func Info(id, policyHash string, expires int64) []byte {
	return []byte(fmt.Sprintf("secrethandoff sealed-request v1|%s|%s|%d", id, policyHash, expires))
}

// FillProof derives the fill proof from the fill secret.
func FillProof(fillSecret []byte) ([]byte, error) {
	return hkdf.Key(sha256.New, fillSecret, nil, "secrethandoff fill-proof v1", 32)
}

func hashB64(b []byte) string {
	sum := sha256.Sum256(b)
	return b64.EncodeToString(sum[:])
}

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// PairingCode is the first 65 bits of SHA-256("sh-pair v1" || public key),
// shown as "XXXXX-XXXX-XXXX" (ADR 0010). 65 bits keep a search for a
// matching key infeasible within a request's lifetime (threat model T-19).
func PairingCode(publicKey []byte) string {
	sum := sha256.Sum256(append([]byte("sh-pair v1"), publicKey...))
	out := make([]byte, 13)
	for group := 0; group < 13; group++ {
		v := 0
		for b := 0; b < 5; b++ {
			bit := group*5 + b
			v = v<<1 | int(sum[bit>>3]>>(7-uint(bit&7))&1)
		}
		out[group] = crockford[v]
	}
	return string(out[:5]) + "-" + string(out[5:9]) + "-" + string(out[9:])
}

// ConfirmationCode is the first 35 bits of SHA-256("sh-fill v1" || id ||
// ciphertext), shown as "XXX-XXXX" (ADR 0011). The fill page shows it after
// a fill; the binary computes it from the ciphertext it picked up.
func ConfirmationCode(id string, ciphertext []byte) string {
	h := sha256.New()
	h.Write([]byte("sh-fill v1"))
	h.Write([]byte(id))
	h.Write(ciphertext)
	sum := h.Sum(nil)
	v := binary.BigEndian.Uint64(append([]byte{0, 0, 0}, sum[:5]...)) >> 5
	out := make([]byte, 7)
	for i := 6; i >= 0; i-- {
		out[i] = crockford[v&31]
		v >>= 5
	}
	return string(out[:3]) + "-" + string(out[3:])
}

// Link returns the fill page link. It carries the public key, the fill
// secret, and the policy hash in the fragment, which browsers never send
// to the server. It never carries the pickup token.
func (r *Request) Link(base string) string {
	return fmt.Sprintf("%s/q/%s#v1.%s.%s.%s", strings.TrimRight(base, "/"), r.ID,
		b64.EncodeToString(r.publicKey), b64.EncodeToString(r.fillSecret), r.PolicyHash)
}

// powInput is the text that the proof of work covers: every field of the
// request, so that one solution cannot create other requests.
func powInput(fillProofHash, pickupHash, policyHash, reasonHash string, expires int64) string {
	return fmt.Sprintf("v2|%s|%s|%s|%s|%d|", fillProofHash, pickupHash, policyHash, reasonHash, expires)
}

// SolvePow finds a nonce for which SHA-256(input + nonce) starts with
// PowBits zero bits.
func SolvePow(input string) string {
	for n := uint64(0); ; n++ {
		nonce := strconv.FormatUint(n, 36)
		if LeadingZeroBits(sha256.Sum256([]byte(input+nonce))) >= PowBits {
			return nonce
		}
	}
}

// LeadingZeroBits counts the zero bits at the start of a digest.
func LeadingZeroBits(sum [32]byte) int {
	n := 0
	for _, b := range sum {
		if b == 0 {
			n += 8
			continue
		}
		return n + bits.LeadingZeros8(b)
	}
	return n
}

// Client talks to the relay service.
type Client struct {
	Base string
	HTTP *http.Client
	// LastConfirmation is the confirmation code of the last Fill.
	LastConfirmation string
}

// NewClient refuses plain HTTP except for loopback test servers.
func NewClient(base string) (*Client, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" {
		return nil, errors.New("invalid relay URL")
	}
	loopback := u.Hostname() == "localhost" || u.Hostname() == "127.0.0.1"
	if u.Scheme != "https" && !(u.Scheme == "http" && loopback) {
		return nil, errors.New("the relay URL must use https")
	}
	return &Client{Base: strings.TrimRight(base, "/"), HTTP: &http.Client{Timeout: 30 * time.Second}}, nil
}

func (c *Client) post(ctx context.Context, path string, body any, out any) (int, error) {
	b, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.Base+path, bytes.NewReader(b))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := c.HTTP.Do(req)
	if err != nil {
		return 0, ErrUnreachable
	}
	defer res.Body.Close()
	data, _ := io.ReadAll(io.LimitReader(res.Body, 256*1024))
	if out != nil && len(data) > 0 {
		json.Unmarshal(data, out) //nolint:errcheck // callers check fields
	}
	return res.StatusCode, nil
}

// Create registers the request with the relay and sets its ID.
func (c *Client) Create(ctx context.Context, r *Request, reason string) error {
	proof, err := FillProof(r.fillSecret)
	if err != nil {
		return err
	}
	fillProofHash, pickupHash := hashB64(proof), hashB64([]byte(r.pickupToken))
	nonce := SolvePow(powInput(fillProofHash, pickupHash, r.PolicyHash, hashB64([]byte(reason)), r.Expires))
	var out struct {
		ID    string `json:"id"`
		Error string `json:"error"`
	}
	code, err := c.post(ctx, "/api/requests", map[string]any{
		"reason": reason, "policy": r.PolicyJSON, "policyHash": r.PolicyHash, "expiresAt": r.Expires,
		"fillProofHash": fillProofHash, "pickupHash": pickupHash, "pow": nonce,
	}, &out)
	if err != nil {
		return err
	}
	if code != http.StatusCreated || out.ID == "" {
		return fmt.Errorf("the relay refused the request: %s", out.Error)
	}
	r.ID = out.ID
	return nil
}

// ErrPending means that nobody has filled the request yet.
var ErrPending = errors.New("not filled yet")

// ErrUnreachable means that the relay service did not answer.
var ErrUnreachable = errors.New("the relay service is not reachable")

// Pickup collects and decrypts the ciphertext once. It returns ErrPending
// while the request is open.
func (c *Client) Pickup(ctx context.Context, r *Request) ([]byte, error) {
	pt, _, err := c.PickupWithCode(ctx, r)
	return pt, err
}

// PickupWithCode is Pickup that also returns the fill confirmation code.
func (c *Client) PickupWithCode(ctx context.Context, r *Request) ([]byte, string, error) {
	var out struct {
		State      string `json:"state"`
		Ciphertext string `json:"ciphertext"`
		Error      string `json:"error"`
	}
	code, err := c.post(ctx, "/api/requests/"+r.ID+"/pickup", map[string]string{"pickupToken": r.pickupToken}, &out)
	if err != nil {
		return nil, "", err
	}
	switch {
	case code == http.StatusAccepted:
		return nil, "", ErrPending
	case code != http.StatusOK:
		return nil, "", fmt.Errorf("the request is no longer available (%s)", strings.TrimSpace(out.State+" "+out.Error))
	}
	ct, err := b64.DecodeString(out.Ciphertext)
	if err != nil {
		return nil, "", errors.New("the relay returned an invalid ciphertext")
	}
	pt, err := r.Open(ct)
	if err != nil {
		return nil, "", err
	}
	return pt, ConfirmationCode(r.ID, ct), nil
}

// Open decrypts a ciphertext for this request. It fails for a ciphertext
// made for another request, policy, or expiry (threat model T-15).
func (r *Request) Open(ciphertext []byte) ([]byte, error) {
	_, kdf, aead := suite()
	pt, err := hpke.Open(r.key, kdf, aead, Info(r.ID, r.PolicyHash, r.Expires), ciphertext)
	if err != nil {
		return nil, errors.New("the ciphertext does not decrypt for this request")
	}
	return pt, nil
}

// Cancel withdraws the request.
func (c *Client) Cancel(ctx context.Context, r *Request) error {
	code, err := c.post(ctx, "/api/requests/"+r.ID+"/cancel", map[string]string{"pickupToken": r.pickupToken}, nil)
	if err == nil && code != http.StatusOK {
		err = fmt.Errorf("cancel returned HTTP %d", code)
	}
	return err
}

// Link parts parsed from a fill link.
type ParsedLink struct {
	Base       string
	ID         string
	PublicKey  []byte
	FillSecret []byte
	PolicyHash string
}

// ParseLink reads https://host/q/<id>#v1.<public key>.<fill secret>.<policy hash>.
func ParseLink(link string) (ParsedLink, error) {
	u, err := url.Parse(strings.TrimSpace(link))
	if err != nil || u.Host == "" || !strings.HasPrefix(u.Path, "/q/") {
		return ParsedLink{}, errors.New("this is not a Secret Handoff request link")
	}
	parts := strings.Split(u.Fragment, ".")
	if len(parts) != 4 || parts[0] != "v1" {
		return ParsedLink{}, errors.New("the link is incomplete; copy the whole link, including the part after #")
	}
	pk, err1 := b64.DecodeString(parts[1])
	fill, err2 := b64.DecodeString(parts[2])
	if err1 != nil || err2 != nil || len(pk) != 65 || len(fill) != 32 || len(parts[3]) != 43 {
		return ParsedLink{}, errors.New("the link is damaged")
	}
	return ParsedLink{Base: u.Scheme + "://" + u.Host, ID: strings.TrimPrefix(u.Path, "/q/"), PublicKey: pk, FillSecret: fill, PolicyHash: parts[3]}, nil
}

// View is what the fill page shows.
type View struct {
	Reason    string `json:"reason"`
	Policy    string `json:"policy"`
	State     string `json:"state"`
	ExpiresAt int64  `json:"expiresAt"`
}

// Fetch loads a request and checks that its policy matches the link.
func (c *Client) Fetch(ctx context.Context, l ParsedLink) (View, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.Base+"/api/requests/"+url.PathEscape(l.ID), nil)
	if err != nil {
		return View{}, err
	}
	res, err := c.HTTP.Do(req)
	if err != nil {
		return View{}, errors.New("the relay service is not reachable")
	}
	defer res.Body.Close()
	var v View
	if res.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(res.Body, 64*1024)).Decode(&v) != nil {
		return View{}, errors.New("this request does not exist or has expired")
	}
	if hashB64([]byte(v.Policy)) != l.PolicyHash {
		return View{}, errors.New("this request was changed after it was created; do not continue")
	}
	return v, nil
}

// Fill seals value for the request's key and sends it with the fill proof
// and a proof of work.
func (c *Client) Fill(ctx context.Context, l ParsedLink, v View, value []byte) error {
	kem, kdf, aead := suite()
	pk, err := kem.NewPublicKey(l.PublicKey)
	if err != nil {
		return errors.New("the link holds an invalid key")
	}
	ct, err := hpke.Seal(pk, kdf, aead, Info(l.ID, l.PolicyHash, v.ExpiresAt), value)
	if err != nil {
		return err
	}
	proof, err := FillProof(l.FillSecret)
	if err != nil {
		return err
	}
	ctB64 := b64.EncodeToString(ct)
	c.LastConfirmation = ConfirmationCode(l.ID, ct)
	nonce := SolvePow("v1fill|" + l.ID + "|" + hashB64([]byte(ctB64)) + "|")
	var out struct {
		Error string `json:"error"`
	}
	code, err := c.post(ctx, "/api/requests/"+url.PathEscape(l.ID)+"/fill", map[string]string{"ciphertext": ctB64, "fillProof": b64.EncodeToString(proof), "pow": nonce}, &out)
	if err != nil {
		return err
	}
	if code != http.StatusOK {
		return fmt.Errorf("the relay refused the fill: %s", out.Error)
	}
	return nil
}
