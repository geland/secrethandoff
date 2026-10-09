package relay

import "strings"

// unsafeRune reports characters that can change how text looks in a
// terminal or a browser: C0 and C1 controls except newline, DEL, bidi
// controls, and zero-width characters. A requester could use them to fake
// or hide a pairing code (review finding 1, threat model T-07).
func unsafeRune(r rune) bool {
	switch {
	case r == '\n':
		return false
	case r < 0x20, r == 0x7f, r >= 0x80 && r <= 0x9f:
		return true
	case r == 0x061c, r >= 0x200b && r <= 0x200f, r >= 0x202a && r <= 0x202e, r >= 0x2066 && r <= 0x2069, r == 0xfeff:
		return true
	}
	return false
}

// HasUnsafeText reports whether s contains a character that unsafeRune
// rejects.
func HasUnsafeText(s string) bool {
	return strings.IndexFunc(s, unsafeRune) >= 0
}

// CleanText removes the characters that unsafeRune rejects.
func CleanText(s string) string {
	return strings.Map(func(r rune) rune {
		if unsafeRune(r) {
			return -1
		}
		return r
	}, s)
}
