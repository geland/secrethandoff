// Package detect finds likely secrets in text, for the Claude Code hooks
// that stop a pasted secret before it reaches the model (threat model T-53).
package detect

import (
	"math"
	"regexp"
	"strings"
)

type rule struct {
	kind string
	re   *regexp.Regexp
}

var rules = []rule{
	{"a private key", regexp.MustCompile(`-----BEGIN (?:[A-Z]+ )*PRIVATE KEY-----`)},
	{"an AWS access key", regexp.MustCompile(`\b(?:AKIA|ASIA)[0-9A-Z]{16}\b`)},
	{"a GitHub token", regexp.MustCompile(`\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{60,})\b`)},
	{"a GitLab token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20,}\b`)},
	{"a Slack token", regexp.MustCompile(`\bxox[abprs]-[A-Za-z0-9-]{10,}\b`)},
	{"a Stripe key", regexp.MustCompile(`\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b`)},
	{"an Anthropic key", regexp.MustCompile(`\bsk-ant-[A-Za-z0-9_-]{20,}`)},
	{"an OpenAI key", regexp.MustCompile(`\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}`)},
	{"a Google API key", regexp.MustCompile(`\bAIza[0-9A-Za-z_-]{35}\b`)},
	{"an npm token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
	{"a JSON Web Token", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},
	{"a URL with a password", regexp.MustCompile(`\b[a-z][a-z0-9+.-]*://[^\s:/@]+:([^\s@/]{6,})@`)},
}

var assignment = regexp.MustCompile(`(?i)\b(?:password|passwd|pwd|secret|token|api[_-]?key|access[_-]?key|client[_-]?secret|auth)\b["']?\s*[:=]\s*["']?([^\s"'` + "`" + `]{12,})`)

var placeholder = regexp.MustCompile(`(?i)example|placeholder|changeme|dummy|redacted|your[_-]|xxxx|<[^>]*>|\$\{|\{\{secret:|\*\*\*|^(?:password|passwd|pass|secret|pwd|admin|root|user|test|token)$`)

// notLiteral matches an assignment value that is not a literal secret: a
// variable or command substitution ($NAME, $(...), %NAME%), or a pattern in a
// filter such as grep or sed (a bracket class, .*, \1, \w, or a group). A
// password that contains such text is missed; the known-format rules above
// still apply to it.
var notLiteral = regexp.MustCompile(`^[$%]|\[[^\]]*\]|\.[*+?{]|\\[A-Za-z0-9()]|\(\?`)

// AllowPhrase in a prompt lets it through on purpose.
const AllowPhrase = "#allow-secret"

// Find returns a description of the first likely secret in text, or "".
// It never returns the secret itself.
func Find(text string) string {
	for _, r := range rules {
		for _, m := range r.re.FindAllStringSubmatch(text, -1) {
			value := m[0]
			if len(m) > 1 && m[1] != "" {
				value = m[1]
			}
			if !placeholder.MatchString(value) {
				return r.kind
			}
		}
	}
	for _, m := range assignment.FindAllStringSubmatch(text, -1) {
		if v := m[1]; !placeholder.MatchString(v) && !notLiteral.MatchString(v) && entropy(v) >= 3.0 && hasMixedClasses(v) {
			return "a password or token"
		}
	}
	return ""
}

// entropy is the Shannon entropy in bits per character.
func entropy(s string) float64 {
	counts := map[rune]int{}
	for _, r := range s {
		counts[r]++
	}
	n := float64(len([]rune(s)))
	h := 0.0
	for _, c := range counts {
		p := float64(c) / n
		h -= p * math.Log2(p)
	}
	return h
}

func hasMixedClasses(s string) bool {
	classes := 0
	for _, set := range []string{"abcdefghijklmnopqrstuvwxyz", "ABCDEFGHIJKLMNOPQRSTUVWXYZ", "0123456789"} {
		if strings.ContainsAny(s, set) {
			classes++
		}
	}
	return classes >= 2
}
