package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const (
	rulesStart = "<!-- secrethandoff:start -->"
	rulesEnd   = "<!-- secrethandoff:end -->"
)

// Guidance layer 4 (plan section 5): a short block for project rule files.
const rulesBlock = rulesStart + `
## Secrets

When you need a password, API key, token, or other credential, or the user offers to paste one, call the ` + "`request_secret`" + ` tool of the secrethandoff MCP server. Never ask the user to paste a secret in the chat.

Use a secret only by name, through ` + "`http_request`" + `, ` + "`proxy_settings`" + ` or ` + "`run_with_secret`" + `. Never print, echo, or write a secret to a file or a commit.

For ` + "`run_with_secret`" + `, supply an absolute ` + "`dir`" + ` and wait for human command approval. Never enable client approval mode yourself.

If a request is pending, call ` + "`wait_for_secret`" + ` with its name. Describe the presentation reported by the result. Chat cards show status; enter secrets only on the Secret Handoff page.
` + rulesEnd + "\n"

const cursorRule = `---
description: How to get and use secrets
alwaysApply: true
---
` + rulesBlock

// runInit writes the rules block into the project's agent rule files in dir.
// It is safe to run more than once: it replaces its own block.
func runInit(dir string, stdout io.Writer) error {
	targets := []string{}
	for _, name := range []string{"AGENTS.md", "CLAUDE.md", "GEMINI.md"} {
		path := filepath.Join(dir, name)
		b, err := os.ReadFile(path)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			return err
		}
		// A CLAUDE.md that imports AGENTS.md already gets the block.
		if name == "CLAUDE.md" && strings.Contains(string(b), "@AGENTS.md") {
			continue
		}
		targets = append(targets, path)
	}
	if len(targets) == 0 {
		targets = append(targets, filepath.Join(dir, "AGENTS.md"))
	}
	for _, path := range targets {
		if err := upsertBlock(path); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "updated", path)
	}
	if st, err := os.Stat(filepath.Join(dir, ".cursor")); err == nil && st.IsDir() {
		path := filepath.Join(dir, ".cursor", "rules", "secrethandoff.mdc")
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile(path, []byte(cursorRule), 0o644); err != nil {
			return err
		}
		fmt.Fprintln(stdout, "updated", path)
	}
	return nil
}

func upsertBlock(path string) error {
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	text := string(b)
	start, end := strings.Index(text, rulesStart), strings.Index(text, rulesEnd)
	switch {
	case start >= 0 && end > start:
		text = text[:start] + rulesBlock + strings.TrimPrefix(text[end+len(rulesEnd):], "\n")
	case start >= 0 || end >= 0:
		return fmt.Errorf("%s has an incomplete secrethandoff block; remove it and run init again", path)
	case text == "":
		text = rulesBlock
	default:
		text = strings.TrimRight(text, "\n") + "\n\n" + rulesBlock
	}
	return os.WriteFile(path, []byte(text), 0o644)
}
