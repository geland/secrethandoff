package secrets

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/url"
	"sort"
	"strings"
)

// minFragment is the shortest encoded fragment that the redactor removes on
// its own. Shorter fragments of base64 text would remove ordinary words.
const minFragment = 8

type pattern struct {
	text string
	name string
}

// Redactor removes secret values and their common encodings from text:
// raw, base64 (standard and URL, padded and not, at every byte offset), hex
// (both cases), URL escaping, and JSON string escaping. It defends against accidents, not against
// a model that tries to hide a value (threat model T-03).
type Redactor struct {
	patterns []pattern
}

func (r *Redactor) add(name string, value []byte) {
	forms := map[string]bool{string(value): true}
	forms[hex.EncodeToString(value)] = true
	forms[strings.ToUpper(hex.EncodeToString(value))] = true
	forms[url.QueryEscape(string(value))] = true
	forms[url.PathEscape(string(value))] = true
	forms[JSONEscape(string(value))] = true
	for _, enc := range []*base64.Encoding{base64.StdEncoding, base64.URLEncoding, base64.RawStdEncoding, base64.RawURLEncoding} {
		for _, core := range base64Cores(enc, value) {
			forms[core] = true
		}
	}
	for f := range forms {
		if f == string(value) || len(f) >= minFragment {
			r.patterns = append(r.patterns, pattern{text: f, name: name})
		}
	}
}

// JSONEscape returns v as the content of a JSON string, without the quotes.
// HTML characters stay as they are.
func JSONEscape(v string) string {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	enc.Encode(v) //nolint:errcheck // a string always encodes
	s := strings.TrimSuffix(b.String(), "\n")
	return s[1 : len(s)-1]
}

// base64Cores returns the part of the base64 text of value that stays the
// same wherever value sits inside a longer byte string, for each of the
// three byte alignments. This catches a secret inside "user:secret" basic
// authentication and similar encodings.
func base64Cores(enc *base64.Encoding, value []byte) []string {
	var out []string
	for offset := 0; offset < 3; offset++ {
		buf := append(make([]byte, offset), value...)
		full := enc.WithPadding(base64.NoPadding).EncodeToString(buf)
		// Characters before this index depend on the prefix bytes.
		start := (offset*8 + 5) / 6
		// Characters at or after this index depend on the bytes after value.
		end := (len(buf) * 8) / 6
		if end-start >= minFragment {
			out = append(out, full[start:end])
		}
	}
	return out
}

func (r *Redactor) sort() {
	// Longer patterns first, so a raw value is replaced before a fragment of
	// its encoding could split it.
	sort.Slice(r.patterns, func(i, j int) bool { return len(r.patterns[i].text) > len(r.patterns[j].text) })
}

// String removes every pattern from s and reports how many it removed.
func (r *Redactor) String(s string) (string, int) {
	if r == nil {
		return s, 0
	}
	n := 0
	for _, p := range r.patterns {
		if c := strings.Count(s, p.text); c > 0 {
			n += c
			s = strings.ReplaceAll(s, p.text, "[REDACTED:"+p.name+"]")
		}
	}
	return s, n
}

// Bytes is String for byte slices.
func (r *Redactor) Bytes(b []byte) ([]byte, int) {
	if r == nil {
		return b, 0
	}
	n := 0
	for _, p := range r.patterns {
		if c := bytes.Count(b, []byte(p.text)); c > 0 {
			n += c
			b = bytes.ReplaceAll(b, []byte(p.text), []byte("[REDACTED:"+p.name+"]"))
		}
	}
	return b, n
}
