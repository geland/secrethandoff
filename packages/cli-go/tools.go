package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"secrethandoff.com/cli/internal/appcard"

	"secrethandoff.com/cli/internal/localpage"
	"secrethandoff.com/cli/internal/policy"
	"secrethandoff.com/cli/internal/relay"
	"secrethandoff.com/cli/internal/secrets"
)

// Every tool result goes through text(), which applies the redactor for all
// secrets held now (AGENTS.md: no secret value in any tool result).
func (s *session) text(isError bool, format string, args ...any) *mcp.CallToolResult {
	msg, _ := s.store.Redactor().String(fmt.Sprintf(format, args...))
	r := &mcp.CallToolResult{IsError: isError, Content: []mcp.Content{&mcp.TextContent{Text: msg}}}
	if isError {
		r.StructuredContent = map[string]any{"status": "error", "message": msg}
	}
	return r
}

// structured applies the same redaction to metadata as to compatibility text.
// Never attach the original object after redaction or a failed JSON decode.
func structured(r *mcp.CallToolResult, value any, redactor *secrets.Redactor) *mcp.CallToolResult {
	b, err := metadataJSON(value)
	if err != nil {
		return r
	}
	clean, _ := redactor.String(string(b))
	var safe map[string]any
	if json.Unmarshal([]byte(clean), &safe) == nil {
		r.StructuredContent = safe
	}
	return r
}

// Match secrets.JSONEscape exactly before redaction. HTML escaping would
// hide a value containing <, >, or & from the redactor, then reveal it when
// the client decodes structuredContent or the list's JSON text.
func metadataJSON(value any) ([]byte, error) {
	var b bytes.Buffer
	enc := json.NewEncoder(&b)
	enc.SetEscapeHTML(false)
	err := enc.Encode(value)
	return b.Bytes(), err
}

func (s *session) lifecycle(status, name, presentation, format string, args ...any) *mcp.CallToolResult {
	r := s.text(status == "error", format, args...)
	out := map[string]any{"status": status, "name": name}
	if presentation != "" {
		out["presentation"] = presentation
	}
	if status == "pending" {
		out["next_tool"] = "wait_for_secret"
		out["next_arguments"] = map[string]any{"name": name}
	} else if status == "confirmation_required" {
		out["next_tool"] = "confirm_secret"
	}
	return structured(r, out, s.store.Redactor())
}

type policyInput struct {
	Hosts   []string `json:"hosts" jsonschema:"Exact host names that may receive the secret, for example api.stripe.com. A wildcard is allowed only as the first label, for example *.example.com."`
	Methods []string `json:"methods,omitempty" jsonschema:"HTTP methods allowed, for example GET and POST. Leave out to allow any method."`
	Paths   []string `json:"paths,omitempty" jsonschema:"URL path patterns allowed, for example /v1/charges or /v1/customers/*. Leave out to allow any path."`
}

type requestSecretInput struct {
	Name             string      `json:"name" jsonschema:"Name for the secret, for example STRIPE_KEY. Letters, digits, and underscores; starts with a letter."`
	Reason           string      `json:"reason" jsonschema:"One sentence that tells the user why the secret is needed."`
	Policy           policyInput `json:"policy" jsonschema:"Where the secret may be sent. Ask for the narrowest policy that does the task."`
	ExpiresInMinutes int         `json:"expires_in_minutes,omitempty" jsonschema:"How long the request stays open, 1 to 60 minutes. Default 10."`
}

type nameInput struct {
	Name string `json:"name" jsonschema:"The secret name."`
}

func addSecretTools(server *mcp.Server, s *session) {
	mcp.AddTool(server, &mcp.Tool{
		Name:        "request_secret",
		Meta:        appcard.ToolMeta(),
		Description: "Request a credential with a name and policy. Reports status and presentation; repeated calls with the same name and policy rejoin the request.",
	}, s.requestSecret)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "wait_for_secret",
		Meta:        appcard.ToolMeta(),
		Description: "Wait for an existing request by name. Cannot open a page or change policy. Returns lifecycle state within the configured timeout.",
	}, s.waitForSecret)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_secrets",
		Description: "List ready secret metadata and pending requests, including remote confirmation.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, s.listSecrets)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "forget_secret",
		Description: "Erase a named secret and cancel its open request. Returns forgotten or missing.",
		Annotations: &mcp.ToolAnnotations{DestructiveHint: ptr(true), IdempotentHint: true},
	}, s.forgetSecret)
	addHTTPTool(server, s)
	addRunTool(server, s)
	addProxyTool(server, s)
	addConfirmTool(server, s)
}

func ptr[T any](v T) *T { return &v }

func (s *session) requestSecret(ctx context.Context, call *mcp.CallToolRequest, in requestSecretInput) (*mcp.CallToolResult, any, error) {
	if !secrets.NamePattern.MatchString(in.Name) {
		return s.text(true, "Invalid name %q. Use letters, digits, and underscores, and start with a letter.", in.Name), nil, nil
	}
	reason := strings.TrimSpace(in.Reason)
	if len(reason) > 500 {
		return s.text(true, "The reason is too long. Use one sentence of 500 characters or fewer."), nil, nil
	}
	if relay.HasUnsafeText(reason) {
		return s.text(true, "The reason contains control or direction characters. Use plain text."), nil, nil
	}
	p, err := policy.Parse(policy.Policy{Hosts: in.Policy.Hosts, Methods: in.Policy.Methods, Paths: in.Policy.Paths})
	if err != nil {
		return s.text(true, "Invalid policy: %v.", err), nil, nil
	}
	ttl := 10 * time.Minute
	if in.ExpiresInMinutes != 0 {
		if in.ExpiresInMinutes < 1 || in.ExpiresInMinutes > 60 {
			return s.text(true, "expires_in_minutes must be 1 to 60."), nil, nil
		}
		ttl = time.Duration(in.ExpiresInMinutes) * time.Minute
	}

	for _, info := range s.store.List() {
		if info.Name == in.Name && info.Policy.Hash() == p.Hash() {
			return s.ready(in.Name, p), nil, nil
		}
	}

	// Without a browser on this computer, use remote mode (ADR 0011).
	if s.available() != nil {
		return s.remoteRequestSecret(ctx, call, in.Name, reason, p, ttl), nil, nil
	}

	s.mu.Lock()
	fr := s.fills[in.Name]
	if fr != nil && (fr.policyHash != p.Hash() || fr.req.State() != localpage.Pending) {
		// A name has one current request. Superseded pages must not refill it
		// later or invoke a rejection callback against its replacement.
		fr.req.Cancel()
		fr = nil
	}
	if fr == nil {
		pages, err := s.pageServer()
		if err != nil {
			s.mu.Unlock()
			return s.text(true, "%v", err), nil, nil
		}
		name := in.Name
		req, err := pages.NewFill(name, reason, p, ttl,
			func(v []byte) error { return s.store.Put(name, v, p) },
			func() { s.store.Forget(name) })
		if err != nil {
			s.mu.Unlock()
			return s.text(true, "Could not open the fill page: %v", err), nil, nil
		}
		fillReq := req
		req.SetRelayStarter(func() (localpage.RelayInfo, error) { return s.startPhoneFill(reason, p, ttl, fillReq) })
		fr = &fillRequest{req: req, policyHash: p.Hash()}
		s.fills[in.Name] = fr
	}
	s.mu.Unlock()

	return s.waitLocal(ctx, in.Name, fr), nil, nil
}

func (s *session) waitLocal(ctx context.Context, name string, fr *fillRequest) *mcp.CallToolResult {
	select {
	case <-fr.req.Done():
	case <-time.After(s.wait):
	case <-ctx.Done():
	}
	switch fr.req.State() {
	case localpage.Filled:
		if !s.store.Has(name) {
			return s.lifecycle("forgotten", name, "browser_page", "%s is no longer available.", name)
		}
		return s.ready(name, fr.req.Policy)
	case localpage.Pending:
		return s.lifecycle("pending", name, "browser_page", "Waiting for the user to fill %s on the Secret Handoff page in their browser. Call wait_for_secret with this name to keep waiting.", name)
	case localpage.Declined:
		return s.lifecycle("declined", name, "browser_page", "The user declined to give %s. Do not ask for it in chat. Ask the user how they want to continue.", name)
	case localpage.Rejected:
		return s.lifecycle("cancelled", name, "browser_page", "The request for %s was cancelled. Any value was discarded. Do not ask for it in chat.", name)
	default:
		return s.lifecycle("expired", name, "browser_page", "The request for %s expired. Call request_secret again if the task still needs it.", name)
	}
}

func (s *session) waitForSecret(ctx context.Context, _ *mcp.CallToolRequest, in nameInput) (*mcp.CallToolResult, any, error) {
	if !secrets.NamePattern.MatchString(in.Name) {
		return s.text(true, "Invalid secret name."), nil, nil
	}
	s.mu.Lock()
	fr, rr := s.fills[in.Name], s.remotes[in.Name]
	s.mu.Unlock()
	if rr != nil {
		return s.waitRemote(ctx, in.Name, rr), nil, nil
	}
	if fr != nil {
		return s.waitLocal(ctx, in.Name, fr), nil, nil
	}
	for _, info := range s.store.List() {
		if info.Name == in.Name {
			return s.ready(in.Name, info.Policy), nil, nil
		}
	}
	return s.lifecycle("missing", in.Name, "", "There is no request or secret named %s. Call request_secret if the task needs it.", in.Name), nil, nil
}

func (s *session) ready(name string, p policy.Policy) *mcp.CallToolResult {
	s.mu.Lock()
	presentation := ""
	if s.fills[name] != nil {
		presentation = "browser_page"
	} else if rr := s.remotes[name]; rr != nil {
		rr.mu.Lock()
		presentation = rr.presentation
		rr.mu.Unlock()
	}
	s.mu.Unlock()
	return s.lifecycle("ready", name, presentation, "%s is ready. %s Use it with http_request by writing {{secret:%s}} in a header, the URL query, or the body. "+
		"Use run_with_secret only when a command must read it from its environment.", name, p.Describe(), name)
}

func (s *session) listSecrets(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
	type pendingInfo struct {
		Name         string `json:"name"`
		Status       string `json:"status"`
		Presentation string `json:"presentation"`
	}
	out := struct {
		Status  string         `json:"status"`
		Ready   []secrets.Info `json:"ready"`
		Pending []pendingInfo  `json:"pending"`
	}{Status: "listed", Ready: s.store.List(), Pending: []pendingInfo{}}
	s.mu.Lock()
	for name, fr := range s.fills {
		if fr.req.State() == localpage.Pending {
			out.Pending = append(out.Pending, pendingInfo{Name: name, Status: "pending", Presentation: "browser_page"})
		}
	}
	for name, rr := range s.remotes {
		rr.mu.Lock()
		if !rr.done && rr.failed == "" {
			status := "pending"
			if rr.value != nil {
				status = "confirmation_required"
			}
			out.Pending = append(out.Pending, pendingInfo{Name: name, Status: status, Presentation: rr.presentation})
		}
		rr.mu.Unlock()
	}
	s.mu.Unlock()
	b, _ := metadataJSON(out)
	return structured(s.text(false, "%s", b), out, s.store.Redactor()), nil, nil
}

func (s *session) forgetSecret(ctx context.Context, _ *mcp.CallToolRequest, in nameInput) (*mcp.CallToolResult, any, error) {
	if !secrets.NamePattern.MatchString(in.Name) {
		return s.text(true, "Invalid secret name."), nil, nil
	}
	s.mu.Lock()
	fr, rr := s.fills[in.Name], s.remotes[in.Name]
	delete(s.fills, in.Name)
	delete(s.remotes, in.Name)
	if fr != nil {
		fr.req.Cancel()
	}
	if rr != nil {
		rr.mu.Lock()
		rr.failed = "cancelled"
		wipe(rr.value)
		rr.value = nil
		rr.mu.Unlock()
	}
	// Snapshot after any in-flight fill finishes, before erasing its value.
	redactor := s.store.Redactor()
	status, message := "forgotten", fmt.Sprintf("%s is erased from memory. Its open request was cancelled.", in.Name)
	if !s.store.Forget(in.Name) && fr == nil && rr == nil {
		status, message = "missing", fmt.Sprintf("There is no secret named %s.", in.Name)
	}
	s.mu.Unlock()
	if rr != nil {
		// Local erasure succeeds even when the relay is unreachable. The relay
		// still enforces its original expiry if cancellation cannot reach it.
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_ = rr.client.Cancel(cctx, rr.req)
		cancel()
	}
	message, _ = redactor.String(message)
	return structured(s.text(false, "%s", message), map[string]any{"status": status, "name": in.Name}, redactor), nil, nil
}
