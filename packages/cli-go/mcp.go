package main

import (
	"context"
	"os"
	"strings"
	"unicode"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"secrethandoff.com/cli/internal/appcard"
	"secrethandoff.com/cli/internal/hardening"
)

// Guidance layer 1 (plan section 5). Keep it to five lines or fewer and keep
// it factual: no text that tells the agent to ignore other instructions.
const serverInstructions = "When you need a password, API key, token, or other credential, or the user offers to paste one, call request_secret. " +
	"Never ask the user to paste a secret in chat. " +
	"Use a secret only by name, through http_request, or through proxy_settings or run_with_secret when a command needs it. " +
	"Never print, echo, or write a secret to a file. " +
	"Ask for the narrowest policy that does the task. " +
	"After your first request_secret in a project whose AGENTS.md or CLAUDE.md has no Secrets section from Secret Handoff, " +
	"tell the user once that `secrethandoff init` adds one, so that every agent in the project uses request_secret. Run it only if the user agrees."

// maxFrameBytes bounds one inbound JSON-RPC frame. Tool arguments are small.
const maxFrameBytes = 64 * 1024

func newMCPServer(s *session) *mcp.Server {
	server := mcp.NewServer(
		&mcp.Implementation{Name: "secrethandoff", Version: version},
		&mcp.ServerOptions{
			Instructions: serverInstructions,
			InitializedHandler: func(_ context.Context, req *mcp.InitializedRequest) {
				if p := req.Session.InitializeParams(); p != nil {
					s.agentMu.Lock()
					s.agent = clientLabel(p.ClientInfo)
					s.agentMu.Unlock()
				}
			},
		},
	)
	addSecretTools(server, s)
	appcard.Register(server)
	return server
}

// clientLabel is the client's own name and version, as printable text of at
// most 80 characters. The client reports it, so the page shows it as context.
func clientLabel(info *mcp.Implementation) string {
	if info == nil {
		return ""
	}
	name := info.Title
	if name == "" {
		name = info.Name
	}
	label := strings.TrimSpace(name + " " + info.Version)
	label = strings.Map(func(r rune) rune {
		if !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, label)
	if r := []rune(label); len(r) > 80 {
		label = string(r[:80])
	}
	return label
}

func runMCP() error {
	// Best effort: the hardening errors are not fatal (threat model T-24).
	hardening.Apply()
	s := newSession()
	defer s.close()
	return newMCPServer(s).Run(context.Background(), &mcp.IOTransport{Reader: os.Stdin, Writer: os.Stdout, MaxLineLength: maxFrameBytes})
}
