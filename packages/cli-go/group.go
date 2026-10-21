package main

import (
	"context"
	"reflect"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"secrethandoff.com/cli/internal/appcard"
	"secrethandoff.com/cli/internal/localpage"
	"secrethandoff.com/cli/internal/policy"
	"secrethandoff.com/cli/internal/relay"
	"secrethandoff.com/cli/internal/secrets"
)

type groupInput struct {
	Name             string            `json:"name" jsonschema:"Unique request name, for example LOGIN. Distinct from every field name. Use this name to wait or forget the entire group."`
	Secrets          []localpage.Field `json:"secrets" jsonschema:"2 to 8 secret fields. Each has a unique name for use by tools and an optional plain-text label. All values stay hidden from the agent."`
	Reason           string            `json:"reason" jsonschema:"One sentence explaining why these credentials are needed."`
	Policy           policyInput       `json:"policy" jsonschema:"One narrow policy shown to the human for every field."`
	ExpiresInMinutes int               `json:"expires_in_minutes,omitempty" jsonschema:"Request deadline, 1 to 60 minutes. Default 10. Filled values remain until forgotten or the session ends."`
}

func addGroupTool(server *mcp.Server, s *session) {
	mcp.AddTool(server, &mcp.Tool{Name: "request_secrets", Meta: appcard.ToolMeta(), Description: "Request 2 to 8 secrets together in one local browser form, for example username and password. One submit publishes all fields atomically with a shared policy. Repeat identical arguments to rejoin. Wait with the request name; forgetting the group or any member erases the whole group. Phone/headless relay fill is not supported for groups."}, s.requestSecrets)
}

func groupNames(fr *fillRequest) []string {
	names := make([]string, 0, len(fr.req.Fields))
	for _, field := range fr.req.Fields {
		names = append(names, field.Name)
	}
	return names
}

// Caller holds s.mu. Cancel takes the same lock as the form's submit callback.
func (s *session) cancelGroupLocked(fr *fillRequest) {
	fr.req.Cancel()
	s.store.ForgetMany(groupNames(fr))
	for name, current := range s.fills {
		if current == fr {
			delete(s.fills, name)
		}
	}
}

func (s *session) requestSecrets(ctx context.Context, _ *mcp.CallToolRequest, in groupInput) (*mcp.CallToolResult, any, error) {
	if !secrets.NamePattern.MatchString(in.Name) {
		return s.text(true, "Invalid grouped request name."), nil, nil
	}
	if len(in.Secrets) < 2 || len(in.Secrets) > localpage.MaxGroupFields {
		return s.text(true, "A grouped request needs 2 to 8 secrets."), nil, nil
	}
	seen := map[string]bool{in.Name: true}
	for i := range in.Secrets {
		f := &in.Secrets[i]
		if !secrets.NamePattern.MatchString(f.Name) || seen[f.Name] {
			return s.text(true, "Field names must be valid, unique, and different from the request name."), nil, nil
		}
		seen[f.Name] = true
		f.Label = strings.TrimSpace(f.Label)
		if f.Label == "" {
			f.Label = f.Name
		}
		if len(f.Label) > 80 || relay.HasUnsafeText(f.Label) {
			return s.text(true, "Field labels must be plain text of at most 80 bytes."), nil, nil
		}
	}
	reason := strings.TrimSpace(in.Reason)
	if len(reason) > 500 || relay.HasUnsafeText(reason) {
		return s.text(true, "Use a plain-text reason of at most 500 bytes."), nil, nil
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
	if s.available() != nil {
		return s.text(true, "Grouped requests require a local browser. Phone and headless relay fill are not supported for groups; no request was created."), nil, nil
	}
	s.mu.Lock()
	fr := s.fills[in.Name]
	if fr != nil && fr.policyHash == p.Hash() && reflect.DeepEqual(fr.req.Fields, in.Secrets) && fr.req.Reason == reason && fr.req.GroupTTL == ttl && (fr.req.State() == localpage.Pending || fr.req.State() == localpage.Filled) {
		s.mu.Unlock()
		return s.waitGroup(ctx, fr), nil, nil
	}
	if s.store.Has(in.Name) {
		s.mu.Unlock()
		return s.text(true, "The request name is already a stored secret. Choose a different group name."), nil, nil
	}
	for name := range seen {
		if s.remotes[name] != nil {
			s.mu.Unlock()
			return s.text(true, "A name already has a remote request. Forget it before starting this group."), nil, nil
		}
	}
	for name := range seen {
		if old := s.fills[name]; old != nil {
			if len(old.req.Fields) != 0 {
				s.cancelGroupLocked(old)
			} else {
				old.req.Cancel()
				delete(s.fills, name)
			}
		}
	}
	pages, err := s.pageServer()
	if err != nil {
		s.mu.Unlock()
		return s.text(true, "Could not start the local group form."), nil, nil
	}
	names := make([]string, len(in.Secrets))
	for i, f := range in.Secrets {
		names[i] = f.Name
	}
	req, err := pages.NewGroup(in.Name, reason, in.Secrets, p, ttl, func(values map[string][]byte) error { return s.store.PutMany(values, p) }, func() { s.store.ForgetMany(names) })
	if err != nil {
		s.mu.Unlock()
		return s.text(true, "Could not open the grouped request page: %v", err), nil, nil
	}
	fr = &fillRequest{req: req, policyHash: p.Hash()}
	s.fills[in.Name] = fr
	for _, name := range names {
		s.fills[name] = fr
	}
	s.mu.Unlock()
	return s.waitGroup(ctx, fr), nil, nil
}

func (s *session) waitGroup(ctx context.Context, fr *fillRequest) *mcp.CallToolResult {
	select {
	case <-fr.req.Done():
	case <-time.After(s.wait):
	case <-ctx.Done():
	}
	status, message := "pending", "Waiting for all fields on one Secret Handoff page. Call wait_for_secret with the grouped request name."
	switch fr.req.State() {
	case localpage.Filled:
		status, message = "ready", "All secrets are ready. Use each field by its name. Forget the request or any member to erase the entire group."
		for _, name := range groupNames(fr) {
			if !s.store.Has(name) {
				status, message = "forgotten", "The grouped secrets are no longer available."
				break
			}
		}
	case localpage.Declined:
		status, message = "declined", "The grouped request was declined. Do not ask for values in chat."
	case localpage.Rejected:
		status, message = "cancelled", "The grouped request was cancelled."
	case localpage.Expired:
		status, message = "expired", "The grouped request expired."
	}
	r := s.lifecycle(status, fr.req.Name, "browser_page", "%s", message)
	out := map[string]any{"status": status, "name": fr.req.Name, "names": groupNames(fr), "presentation": "browser_page"}
	if status == "pending" {
		out["next_tool"] = "wait_for_secret"
		out["next_arguments"] = map[string]any{"name": fr.req.Name}
	}
	return structured(r, out, s.store.Redactor())
}
