package main

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"secrethandoff.com/cli/internal/appcard"

	"secrethandoff.com/cli/internal/policy"
	"secrethandoff.com/cli/internal/relay"
)

const maxConfirmAttempts = 5

// remoteRequest is a request in remote mode (ADR 0011). A picked-up value
// waits here, apart from the ready secrets, until the human's confirmation
// code arrives. The binary never tells the agent the expected code.
type remoteRequest struct {
	mu           sync.Mutex
	poll         chan struct{}
	client       *relay.Client
	req          *relay.Request
	policy       policy.Policy
	policyHash   string
	value        []byte
	expected     string
	attempts     int
	done         bool
	failed       string
	presentation string
}

func (s *session) remoteRequestSecret(ctx context.Context, call *mcp.CallToolRequest, name, reason string, p policy.Policy, ttl time.Duration) *mcp.CallToolResult {
	s.mu.Lock()
	rr := s.remotes[name]
	var superseded *remoteRequest
	if rr != nil && rr.policyHash != p.Hash() {
		superseded = rr
		delete(s.remotes, name)
		rr.mu.Lock()
		rr.failed = "cancelled"
		wipe(rr.value)
		rr.value = nil
		rr.mu.Unlock()
		rr = nil
	}
	s.mu.Unlock()
	if superseded != nil {
		cctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		_ = superseded.client.Cancel(cctx, superseded.req)
		cancel()
	}

	if rr == nil {
		client, err := relay.NewClient(s.relayURL)
		if err != nil {
			return s.text(true, "%v", err)
		}
		if ttl > relay.MaxLifetime {
			ttl = relay.MaxLifetime
		}
		policyJSON, _ := json.Marshal(p)
		r, err := relay.New(string(policyJSON), ttl)
		if err != nil {
			return s.text(true, "%v", err)
		}
		cctx, cancel := context.WithTimeout(ctx, 30*time.Second)
		err = client.Create(cctx, r, reason)
		cancel()
		if err != nil {
			return s.text(true, "This computer has no browser, and the phone relay is not available: %v", err)
		}
		rr = &remoteRequest{client: client, req: r, policy: p, policyHash: p.Hash(), presentation: "remote_link", poll: make(chan struct{}, 1)}
		s.mu.Lock()
		s.remotes[name] = rr
		s.mu.Unlock()

		link, code := r.Link(s.relayURL), relay.PairingCode(r.PublicKey())
		if res := s.elicitURL(ctx, call, name, reason, link, code); res != nil {
			rr.mu.Lock()
			rr.presentation = "client_prompt"
			rr.mu.Unlock()
			return res
		}
		return s.lifecycle("pending", name, "remote_link", "This computer has no browser. Ask the user to open this link on their phone or another computer, and to continue only if the page shows the pairing code %s:\n%s\n\n"+
			"Then call wait_for_secret with this name to wait. Do not ask for the secret in chat.", code, link)
	}
	return s.waitRemote(ctx, name, rr)
}

// elicitURL sends the link through MCP URL-mode elicitation when the client
// supports it, so that the link stays out of the model context. It returns
// nil when the client does not support it, and the caller then puts the
// link in the tool result.
func (s *session) elicitURL(ctx context.Context, call *mcp.CallToolRequest, name, reason, link, code string) *mcp.CallToolResult {
	if call == nil || call.Session == nil {
		return nil
	}
	params := call.Session.InitializeParams()
	if params == nil || params.Capabilities == nil || params.Capabilities.Elicitation == nil || params.Capabilities.Elicitation.URL == nil {
		return nil
	}
	elicit := &mcp.ElicitParams{
		Mode:          "url",
		Message:       fmt.Sprintf("Your agent asks for %s: %s Open the page and continue only if it shows the pairing code %s.", name, reason, code),
		URL:           link,
		ElicitationID: code,
	}
	waiting := s.lifecycle("pending", name, "client_prompt", "The user's agent client is showing a page to give %s, with pairing code %s. "+
		"Call wait_for_secret with this name to wait for it. Do not ask for the secret in chat.", name, code)
	// From protocol 2026-07-28, a server returns input requests in the
	// result (multi round-trip, SEP-2322). The client shows the page and
	// retries the call, which rejoins this request.
	if params.ProtocolVersion >= "2026-07-28" {
		// An input-required result carries no content.
		return &mcp.CallToolResult{InputRequests: mcp.InputRequestMap{"open-fill-page": elicit}}
	}
	ectx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	if _, err := call.Session.Elicit(ectx, elicit); err != nil {
		return nil
	}
	return waiting
}

func (s *session) waitRemote(ctx context.Context, name string, rr *remoteRequest) *mcp.CallToolResult {
	// The budget includes time queued behind another waiter and relay I/O.
	ctx, stop := context.WithTimeout(ctx, s.wait)
	defer stop()
	// Only one call may pick up a remote ciphertext at a time.
	select {
	case rr.poll <- struct{}{}:
		defer func() { <-rr.poll }()
	case <-ctx.Done():
		rr.mu.Lock()
		presentation := rr.presentation
		rr.mu.Unlock()
		return s.lifecycle("pending", name, presentation, "Waiting for the user to fill %s on their other device. Call wait_for_secret with this name to keep waiting.", name)
	}
	deadline := time.Now().Add(s.wait)
	for {
		rr.mu.Lock()
		done, failed, hasValue, presentation := rr.done, rr.failed, rr.value != nil, rr.presentation
		rr.mu.Unlock()
		switch {
		case failed != "":
			s.dropRemoteIf(name, rr)
			status := "error"
			if failed == "cancelled" {
				status = "cancelled"
			} else if strings.Contains(failed, "expired") {
				status = "expired"
			}
			return s.lifecycle(status, name, presentation, "The request for %s ended: %s. Call request_secret again if the task still needs it.", name, failed)
		case done:
			return s.ready(name, rr.policy)
		case hasValue:
			return s.lifecycle("confirmation_required", name, presentation, "The user filled %s. Before you use it, ask the user for the confirmation code that their page showed after they sent the secret, "+
				"then call confirm_secret with that code. Do not guess the code.", name)
		}
		pctx, cancel := context.WithTimeout(ctx, 20*time.Second)
		value, code, err := rr.client.PickupWithCode(pctx, rr.req)
		cancel()
		switch {
		case err == nil:
			rr.mu.Lock()
			if rr.failed != "" {
				wipe(value)
			} else {
				rr.value, rr.expected = value, code
			}
			rr.mu.Unlock()
			continue
		case !errors.Is(err, relay.ErrPending):
			if ctx.Err() != nil {
				return s.lifecycle("pending", name, presentation, "Waiting for the user to fill %s on their other device. Call wait_for_secret with this name to keep waiting.", name)
			}
			rr.mu.Lock()
			if rr.failed == "" {
				rr.failed = err.Error()
			}
			rr.mu.Unlock()
			continue
		}
		if time.Now().After(deadline) || ctx.Err() != nil {
			return s.lifecycle("pending", name, presentation, "Waiting for the user to fill %s on their other device. Call wait_for_secret with this name to keep waiting. Do not ask for the secret in chat.", name)
		}
		select {
		case <-time.After(2 * time.Second):
		case <-ctx.Done():
		}
	}
}

func (s *session) dropRemote(name string) {
	s.dropRemoteIf(name, nil)
}

// A waiter for an old request must never remove a replacement of that name.
func (s *session) dropRemoteIf(name string, expected *remoteRequest) {
	s.mu.Lock()
	rr := s.remotes[name]
	if expected != nil && rr != expected {
		s.mu.Unlock()
		return
	}
	delete(s.remotes, name)
	s.mu.Unlock()
	if rr != nil {
		rr.mu.Lock()
		rr.failed = "cancelled"
		wipe(rr.value)
		rr.value = nil
		rr.mu.Unlock()
	}
}

type confirmInput struct {
	Name string `json:"name" jsonschema:"The secret name."`
	Code string `json:"code" jsonschema:"The confirmation code exactly as the user read it from their page, for example 7KQ-2XRA."`
}

func addConfirmTool(server *mcp.Server, s *session) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "confirm_secret",
		Meta: appcard.ToolMeta(),
		Description: "Confirm a secret that the user filled on another device, with the confirmation code that the user read from their page. " +
			"Only the user knows this code; never guess it.",
	}, s.confirmSecret)
}

func normalizeCode(c string) string {
	return strings.ToUpper(strings.NewReplacer("-", "", " ", "").Replace(strings.TrimSpace(c)))
}

func (s *session) confirmSecret(_ context.Context, _ *mcp.CallToolRequest, in confirmInput) (*mcp.CallToolResult, any, error) {
	s.mu.Lock()
	rr := s.remotes[in.Name]
	s.mu.Unlock()
	if rr == nil {
		return s.text(true, "There is no filled request named %s that waits for confirmation.", in.Name), nil, nil
	}
	rr.mu.Lock()
	if rr.value == nil || rr.done {
		rr.mu.Unlock()
		return s.text(true, "%s is not waiting for confirmation.", in.Name), nil, nil
	}
	if subtle.ConstantTimeCompare([]byte(normalizeCode(in.Code)), []byte(normalizeCode(rr.expected))) != 1 {
		rr.attempts++
		left := maxConfirmAttempts - rr.attempts
		rr.mu.Unlock()
		if left <= 0 {
			s.dropRemote(in.Name)
			return s.text(true, "Too many wrong codes. The value for %s was discarded. Ask the user whether someone else filled the request, then call request_secret again.", in.Name), nil, nil
		}
		return s.text(true, "That code does not match. Ask the user to read the code again from their page. %d attempts remain.", left), nil, nil
	}
	err := s.store.Put(in.Name, rr.value, rr.policy)
	wipe(rr.value)
	rr.value, rr.done = nil, true
	rr.mu.Unlock()
	if err != nil {
		return s.text(true, "%v", err), nil, nil
	}
	return s.ready(in.Name, rr.policy), nil, nil
}

func wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}
