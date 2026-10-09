package main

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"secrethandoff.com/cli/internal/detect"
)

// Claude Code hooks (plan task P1-11, threat model T-53). The output names
// the kind of secret, never the value.

type hookInput struct {
	Prompt    string `json:"prompt"`
	ToolInput struct {
		Command string `json:"command"`
	} `json:"tool_input"`
}

func runHook(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) != 1 || (args[0] != "user-prompt" && args[0] != "bash") {
		fmt.Fprintln(stderr, "usage: secrethandoff hook user-prompt|bash")
		return 2
	}
	var in hookInput
	if err := json.NewDecoder(io.LimitReader(stdin, 4<<20)).Decode(&in); err != nil {
		// Never block the user because of a malformed hook input.
		return 0
	}
	switch args[0] {
	case "user-prompt":
		if strings.Contains(in.Prompt, detect.AllowPhrase) {
			return 0
		}
		kind := detect.Find(in.Prompt)
		if kind == "" {
			return 0
		}
		json.NewEncoder(stdout).Encode(map[string]any{ //nolint:errcheck
			"decision": "block",
			"reason": "This message looks like it contains " + kind + ", so it was not sent to the AI. " +
				"It is still saved in this session's local history, so treat it as exposed and replace it if it matters. " +
				"Ask the agent to use request_secret instead, or add " + detect.AllowPhrase + " to send the message anyway.",
			"hookSpecificOutput": map[string]any{"hookEventName": "UserPromptSubmit", "suppressOriginalPrompt": true},
		})
	case "bash":
		kind := detect.Find(in.ToolInput.Command)
		if kind == "" {
			return 0
		}
		json.NewEncoder(stdout).Encode(map[string]any{ //nolint:errcheck
			"hookSpecificOutput": map[string]any{
				"hookEventName":            "PreToolUse",
				"permissionDecision":       "deny",
				"permissionDecisionReason": "This command contains " + kind + " as literal text. Call request_secret, then use the secret by name through http_request or run_with_secret.",
			},
		})
	}
	return 0
}
