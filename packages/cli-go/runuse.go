package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"secrethandoff.com/cli/internal/appcard"

	"secrethandoff.com/cli/internal/localpage"
	"secrethandoff.com/cli/internal/policy"
	"secrethandoff.com/cli/internal/secrets"
)

var envName = regexp.MustCompile(`^[A-Z_][A-Z0-9_]{0,63}$`)

// Variables that change how a program loads or runs. A secret may not
// replace them.
var protectedEnv = regexp.MustCompile(`^(PATH|HOME|SHELL|IFS|ENV|BASH_ENV|NODE_OPTIONS|PYTHONPATH|PYTHONSTARTUP|PERL5OPT|RUBYOPT|LD_.*|DYLD_.*|GIT_.*|SSL_CERT_FILE|SSL_CERT_DIR|HTTPS?_PROXY|ALL_PROXY|NO_PROXY)$`)

const maxCommandOutput = 32 * 1024

type runInput struct {
	Command        []string `json:"command" jsonschema:"The program and its arguments, one item each. No shell is used, so pipes and variables are not expanded. Standard input is empty."`
	Secrets        []string `json:"secrets" jsonschema:"Secrets for the command's environment, each as NAME:ENV_VAR, for example DB_PASSWORD:PGPASSWORD."`
	Dir            string   `json:"dir,omitempty" jsonschema:"Working folder. Default is the folder where the MCP server started."`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty" jsonschema:"1 to 600 seconds. Default 60."`
}

type envBinding struct{ name, env string }

func addRunTool(server *mcp.Server, s *session) {
	meta := appcard.ToolMeta()
	if s.commandApproval == "claude-code" {
		// Unlike form elicitation, Claude Code's mandatory permission prompt
		// cannot be accepted by an allow rule or a PreToolUse allow hook.
		meta["anthropic/requiresUserInteraction"] = true
	}
	mcp.AddTool(server, &mcp.Tool{
		Name: "run_with_secret",
		Meta: meta,
		Description: "Run one command with secrets in its environment after human approval, in the browser or an owner-enabled Claude Code permission prompt. " +
			"Use it only when a program must read a secret from its environment; prefer http_request. " +
			"Pass an explicit absolute dir for client approval. A command that holds a secret can send it anywhere; its network policy is not enforced. " +
			"Returns the exit code and the output with every secret value removed. Calling again with the same arguments rejoins an open approval.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(true), OpenWorldHint: ptr(true)},
	}, s.runWithSecret)
}

func (s *session) runWithSecret(ctx context.Context, call *mcp.CallToolRequest, in runInput) (*mcp.CallToolResult, any, error) {
	if len(in.Command) == 0 || strings.TrimSpace(in.Command[0]) == "" {
		return s.text(true, "command needs at least the program name."), nil, nil
	}
	timeout := 60 * time.Second
	if in.TimeoutSeconds != 0 {
		if in.TimeoutSeconds < 1 || in.TimeoutSeconds > 600 {
			return s.text(true, "timeout_seconds must be 1 to 600."), nil, nil
		}
		timeout = time.Duration(in.TimeoutSeconds) * time.Second
	}
	bindings, err := s.parseBindings(in.Secrets)
	if err != nil {
		return s.text(true, "%v", err), nil, nil
	}
	dir := in.Dir
	if dir == "" {
		dir, _ = os.Getwd()
	}
	if st, err := os.Stat(dir); err != nil || !st.IsDir() {
		return s.text(true, "The folder %s does not exist.", dir), nil, nil
	}
	if ctx.Err() != nil {
		return s.text(true, "The call was cancelled. The command did not run."), nil, nil
	}
	if s.clientCommandApproval(call, in.Dir) {
		// The trusted host gates this tools/call itself. There is deliberately
		// no approve tool, Boolean argument, form response, or remembered grant.
		return s.execute(ctx, in.Command, dir, bindings, timeout, "client_permission"), nil, nil
	}

	key := approvalKey(in.Command, dir, in.Secrets, timeout)
	s.mu.Lock()
	req := s.approvals[key]
	if req != nil && req.State() != localpage.Pending && req.State() != localpage.Approved {
		req = nil
	}
	if req == nil {
		pages, err := s.pageServer()
		if err != nil {
			s.mu.Unlock()
			return s.text(true, "%v", err), nil, nil
		}
		names := make([]string, 0, len(bindings))
		for _, b := range bindings {
			names = append(names, b.name+" as "+b.env)
		}
		req, err = pages.NewApproval(in.Command, dir, names, 10*time.Minute)
		if err != nil {
			s.mu.Unlock()
			return s.text(true, "Could not open the approval page: %v", err), nil, nil
		}
		s.approvals[key] = req
	}
	s.mu.Unlock()

	select {
	case <-req.Done():
	case <-time.After(s.wait):
	case <-ctx.Done():
	}
	switch req.State() {
	case localpage.Approved:
		// One approval runs the command once.
		if ctx.Err() != nil || !s.takeCommandApproval(key, req) {
			return s.text(true, "This approval was already used or the call was cancelled. The command did not run."), nil, nil
		}
		return s.execute(ctx, in.Command, dir, bindings, timeout, "browser_page"), nil, nil
	case localpage.Pending:
		if ctx.Err() != nil {
			return s.commandNotRun("command_cancelled", "cancelled", "The call was cancelled. The command did not run. Its approval page remains open."), nil, nil
		}
		return s.commandNotRun("command_pending", "pending", "Waiting for the user to approve the command in their browser. Call run_with_secret again with the same arguments to keep waiting."), nil, nil
	case localpage.Denied, localpage.Rejected:
		return s.commandNotRun("command_denied", "denied", "The user did not approve this command. It did not run. Ask the user how they want to continue."), nil, nil
	default:
		return s.commandNotRun("command_expired", "expired", "The approval request expired. The command did not run."), nil, nil
	}
}

// takeCommandApproval atomically consumes the particular page's grant.
// Concurrent waiters and waiters for an older page cannot reuse it.
func (s *session) takeCommandApproval(key string, req *localpage.Request) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.approvals[key] != req {
		return false
	}
	delete(s.approvals, key)
	return true
}

func (s *session) parseBindings(list []string) ([]envBinding, error) {
	if len(list) == 0 {
		return nil, errors.New("secrets needs at least one NAME:ENV_VAR pair; use your own tools for commands that need no secret")
	}
	seen := map[string]bool{}
	var out []envBinding
	for _, item := range list {
		name, env, ok := strings.Cut(item, ":")
		if !ok || !secrets.NamePattern.MatchString(name) || !envName.MatchString(env) {
			return nil, fmt.Errorf("%q must be NAME:ENV_VAR, with ENV_VAR in capital letters, digits, and underscores", item)
		}
		if protectedEnv.MatchString(env) {
			return nil, fmt.Errorf("%s cannot hold a secret, because it changes how programs run", env)
		}
		if seen[env] {
			return nil, fmt.Errorf("%s is used twice", env)
		}
		if !s.store.Has(name) {
			return nil, fmt.Errorf("no secret named %s; call request_secret first", name)
		}
		seen[env] = true
		out = append(out, envBinding{name: name, env: env})
	}
	return out, nil
}

func approvalKey(command []string, dir string, secretList []string, timeout time.Duration) string {
	b, _ := json.Marshal([]any{command, dir, secretList, timeout})
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// clientCommandApproval trusts the owner's chosen interactive Claude Code
// host, not a generic elicitation capability or a client-provided approval bit.
// 2.1.284 is the oldest targeted build; live host acceptance is required before
// opting in. SDK/custom permission hosts must keep browser mode: their
// canUseTool callback can approve without a human.
func (s *session) clientCommandApproval(call *mcp.CallToolRequest, dir string) bool {
	if s.commandApproval != "claude-code" || call == nil || call.Session == nil || !filepath.IsAbs(dir) || filepath.Clean(dir) != dir {
		return false
	}
	p := call.Session.InitializeParams()
	if p == nil || p.ClientInfo == nil || p.ClientInfo.Name != "claude-code" {
		return false
	}
	var major, minor, patch int
	if _, err := fmt.Sscanf(p.ClientInfo.Version, "%d.%d.%d", &major, &minor, &patch); err != nil {
		return false
	}
	// Do not infer support across minor/major releases or from pre-release labels.
	if p.ClientInfo.Version != fmt.Sprintf("%d.%d.%d", major, minor, patch) {
		return false
	}
	return major == 2 && minor == 1 && patch >= 284
}

func (s *session) commandNotRun(status, approval, message string) *mcp.CallToolResult {
	return structured(s.text(false, "%s", message), map[string]any{
		"status": status, "presentation": "browser_page", "approval": approval,
		"executed": false, "message": message,
	}, s.store.Redactor())
}

type capped struct {
	buf   bytes.Buffer
	limit int
	over  bool
}

func (c *capped) Write(p []byte) (int, error) {
	if room := c.limit - c.buf.Len(); room > 0 {
		if len(p) > room {
			c.buf.Write(p[:room])
			c.over = true
		} else {
			c.buf.Write(p)
		}
	} else if len(p) > 0 {
		c.over = true
	}
	return len(p), nil
}

func (s *session) execute(ctx context.Context, command []string, dir string, bindings []envBinding, timeout time.Duration, presentation string) *mcp.CallToolResult {
	// Keep the redaction snapshot through execution even if the owner forgets
	// or replaces a secret while the child still holds it in its environment.
	redactor := s.store.Redactor()
	finish := func(result *mcp.CallToolResult, data map[string]any) *mcp.CallToolResult {
		data["presentation"] = presentation
		data["approval"] = "approved"
		// Hosts may show just structuredContent. It must carry the complete
		// outcome, redacted for both the values used and those currently held.
		structured(result, data, redactor)
		return structured(result, result.StructuredContent, s.store.Redactor())
	}
	notStarted := func(message string) *mcp.CallToolResult {
		message, _ = redactor.String(message)
		return finish(s.text(true, "%s", message), map[string]any{
			"status": "command_not_started", "executed": false, "message": message,
			"timed_out": ctx.Err() == context.DeadlineExceeded, "cancelled": ctx.Err() == context.Canceled,
		})
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Dir = dir
	// Standard input stays empty (the null device). A child process that
	// keeps the output pipes open after the stop must not hold the call.
	prepareProcess(cmd)
	cmd.WaitDelay = 3 * time.Second
	env := os.Environ()
	for _, b := range bindings {
		if err := s.store.UseWithRedactor(b.name, redactor, func(v []byte, _ policy.Policy) error {
			env = append(env, b.env+"="+string(v))
			return nil
		}); err != nil {
			return notStarted(err.Error())
		}
	}
	cmd.Env = env
	stdout, stderr := &capped{limit: maxCommandOutput}, &capped{limit: maxCommandOutput}
	cmd.Stdout, cmd.Stderr = stdout, stderr
	runErr := cmd.Run()
	if cmd.Process == nil {
		return notStarted(fmt.Sprintf("The command could not start: %v", runErr))
	}

	code := 0
	var exitErr *exec.ExitError
	switch {
	case runErr == nil:
	case errors.As(runErr, &exitErr):
		code = exitErr.ExitCode()
	case ctx.Err() != nil, errors.Is(runErr, exec.ErrWaitDelay):
		code = -1
	default:
		return notStarted(fmt.Sprintf("The command could not start: %v", runErr))
	}
	var b strings.Builder
	switch {
	case ctx.Err() == context.DeadlineExceeded:
		fmt.Fprintf(&b, "The command did not finish within %d seconds. It was stopped, with the processes that it started. "+
			"Its output so far is below. Its standard input is empty, so a command that waits for input or for a terminal, "+
			"such as an interactive session, cannot finish. Use a form of the command that does not wait for input.\n", int(timeout/time.Second))
	case ctx.Err() != nil:
		b.WriteString("The call was cancelled before the command finished. The command was stopped. Its output so far is below.\n")
	}
	fmt.Fprintf(&b, "exit code: %d\n", code)
	for _, part := range []struct {
		label string
		c     *capped
	}{{"stdout", stdout}, {"stderr", stderr}} {
		fmt.Fprintf(&b, "--- %s ---\n%s\n", part.label, part.c.buf.String())
		if part.c.over {
			fmt.Fprintf(&b, "[%s truncated at %d bytes]\n", part.label, maxCommandOutput)
		}
	}
	out, n := redactor.String(b.String())
	// Also cover secrets filled since the command began.
	currentRedactor := s.store.Redactor()
	out, additional := currentRedactor.String(out)
	n += additional
	if n > 0 {
		out += fmt.Sprintf("\n[%d secret value(s) removed from the output]\n", n)
	}
	redactedStdout, _ := redactor.String(stdout.buf.String())
	redactedStderr, _ := redactor.String(stderr.buf.String())
	result := &mcp.CallToolResult{IsError: code != 0 || ctx.Err() != nil, Content: []mcp.Content{&mcp.TextContent{Text: out}}}
	return finish(result, map[string]any{
		"status": "command_finished", "executed": cmd.Process != nil, "exit_code": code,
		"stdout": redactedStdout, "stderr": redactedStderr,
		"stdout_truncated": stdout.over, "stderr_truncated": stderr.over,
		"timed_out": ctx.Err() == context.DeadlineExceeded, "cancelled": ctx.Err() == context.Canceled,
	})
}
