package main

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func hook(t *testing.T, kind string, input any) (int, map[string]any, string) {
	t.Helper()
	b, _ := json.Marshal(input)
	var out, errOut bytes.Buffer
	code := runWithInput([]string{"hook", kind}, bytes.NewReader(b), &out, &errOut)
	var decoded map[string]any
	if out.Len() > 0 {
		if err := json.Unmarshal(out.Bytes(), &decoded); err != nil {
			t.Fatalf("hook output is not JSON: %s", out.String())
		}
	}
	return code, decoded, out.String()
}

func TestUserPromptHook(t *testing.T) {
	value := "ghp_" + "aB3dE5fG7hI9jK1lM3nO5pQ7rS9tU1vW3xY5"
	code, out, raw := hook(t, "user-prompt", map[string]string{"prompt": "deploy with " + value})
	if code != 0 || out["decision"] != "block" || strings.Contains(raw, value) || !strings.Contains(raw, "a GitHub token") {
		t.Fatalf("block: %s", raw)
	}
	if hso := out["hookSpecificOutput"].(map[string]any); hso["suppressOriginalPrompt"] != true {
		t.Fatal("suppressOriginalPrompt not set")
	}
	if _, out, _ := hook(t, "user-prompt", map[string]string{"prompt": "deploy with " + value + " #allow-secret"}); out != nil {
		t.Fatal("the allow phrase did not let the prompt through")
	}
	if _, out, _ := hook(t, "user-prompt", map[string]string{"prompt": "fix the tests"}); out != nil {
		t.Fatal("blocked a normal prompt")
	}
}

func TestBashHook(t *testing.T) {
	value := "sk_live_" + "51Hx9ZqLkJv8Q2wE7rT5yU3i"
	_, out, raw := hook(t, "bash", map[string]any{"tool_input": map[string]string{"command": "curl -H 'Authorization: Bearer " + value + "' https://api.stripe.com"}})
	hso, _ := out["hookSpecificOutput"].(map[string]any)
	if hso["permissionDecision"] != "deny" || strings.Contains(raw, value) {
		t.Fatalf("deny: %s", raw)
	}
	if _, out, _ := hook(t, "bash", map[string]any{"tool_input": map[string]string{"command": "npm test"}}); out != nil {
		t.Fatal("denied a normal command")
	}
	var errOut bytes.Buffer
	if code := runWithInput([]string{"hook", "bash"}, strings.NewReader("not json"), &bytes.Buffer{}, &errOut); code != 0 {
		t.Fatal("malformed input must not block")
	}
}
