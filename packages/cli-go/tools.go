package main

import (
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
	return &mcp.CallToolResult{IsError: isError, Content: []mcp.Content{&mcp.TextContent{Text: msg}}}
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
		Name: "request_secret",
		Meta: appcard.ToolMeta(),
		Description: "Ask the user for a credential through a page in their browser. The value never enters the conversation. " +
			"Returns when the secret is ready to use by name, or tells you to call again to keep waiting. " +
			"Calling again with the same name and policy rejoins the open request.",
	}, s.requestSecret)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "list_secrets",
		Description: "List the secrets that are ready, with their policies, and the requests that are still open. Never returns values.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, s.listSecrets)
	mcp.AddTool(server, &mcp.Tool{
		Name:        "forget_secret",
		Description: "Erase a secret from memory. Use it when the task no longer needs the secret.",
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

	select {
	case <-fr.req.Done():
	case <-time.After(s.wait):
	case <-ctx.Done():
	}
	switch fr.req.State() {
	case localpage.Filled:
		return s.ready(in.Name, p), nil, nil
	case localpage.Pending:
		return s.text(false, "Waiting for the user to fill %s on the page that opened in their browser. "+
			"Call request_secret again with the same name and policy to keep waiting. Do not ask for the secret in chat.", in.Name), nil, nil
	case localpage.Declined:
		return s.text(false, "The user declined to give %s. Do not ask for it in chat. Ask the user how they want to continue.", in.Name), nil, nil
	case localpage.Rejected:
		return s.text(false, "The user cancelled the request for %s. Any value was discarded. Do not ask for it in chat.", in.Name), nil, nil
	default:
		return s.text(false, "The request for %s expired. Call request_secret again if the task still needs it.", in.Name), nil, nil
	}
}

func (s *session) ready(name string, p policy.Policy) *mcp.CallToolResult {
	return s.text(false, "%s is ready. %s Use it with http_request by writing {{secret:%s}} in a header, the URL query, or the body. "+
		"Use run_with_secret only when a command must read it from its environment.", name, p.Describe(), name)
}

func (s *session) listSecrets(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
	type pendingInfo struct {
		Name string `json:"name"`
	}
	out := struct {
		Ready   []secrets.Info `json:"ready"`
		Pending []pendingInfo  `json:"pending"`
	}{Ready: s.store.List(), Pending: []pendingInfo{}}
	s.mu.Lock()
	for name, fr := range s.fills {
		if fr.req.State() == localpage.Pending {
			out.Pending = append(out.Pending, pendingInfo{Name: name})
		}
	}
	s.mu.Unlock()
	b, _ := json.Marshal(out)
	return s.text(false, "%s", b), nil, nil
}

func (s *session) forgetSecret(_ context.Context, _ *mcp.CallToolRequest, in nameInput) (*mcp.CallToolResult, any, error) {
	s.dropRemote(in.Name)
	if !s.store.Forget(in.Name) {
		return s.text(false, "There is no secret named %s.", in.Name), nil, nil
	}
	return s.text(false, "%s is erased from memory.", in.Name), nil, nil
}
