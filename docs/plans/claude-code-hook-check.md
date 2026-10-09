# Claude Code hook check (task P0-6)

- Date: 2026-10-07
- Client: Claude Code 2.1.289, desktop app
- Method: a test plugin with a `UserPromptSubmit` hook and a `PreToolUse` hook for `Bash`. Both hooks matched only a fake marker (`SHPROBE_` followed by 8 or more letters or digits). No real secrets were used.

## Results

| Check | Result |
|---|---|
| Plugin hooks load from a plugin's `hooks/hooks.json` | Yes |
| `UserPromptSubmit` input field for the text | `prompt` |
| A prompt with the marker is blocked with `decision: "block"` | Yes. The model did not receive it. |
| The block message contains the prompt text when `suppressOriginalPrompt: true` | No |
| The prompt text is written to disk | **Yes.** The session transcript (`~/.claude/projects/<project>/<session>.jsonl`) has a `queue-operation` record with the full text. The desktop app writes it when the user sends the message, before the hook runs. |
| The prompt text is in `~/.claude/history.jsonl` | No |
| `PreToolUse` denies a Bash command with the marker through `permissionDecision: "deny"` | Yes. The command did not run, and the model received `permissionDecisionReason`. |

The Claude Code hooks documentation says the same: a blocked prompt never reaches the model, but a blocking hook does not keep a secret off disk.

## Effects on the plan

1. **Task P1-11 stays a block, not a warning.** The hook keeps a pasted secret out of the model context, which is goal G2.
2. **The hook cannot keep the secret off disk.** The block message must say so plainly, for example: "This message looks like it contains a secret. It was not sent to the AI. It is still saved in this session's local history, so treat it as exposed and replace it if it matters. Use request_secret instead."
3. **Public claims for the hook:** "Stops a pasted secret before it reaches the AI model." Do not claim that the hook removes the secret from the computer.
4. **Test hygiene.** Tests must count marker matches and never print them. In this check, printing the match put the marker into the model context.
