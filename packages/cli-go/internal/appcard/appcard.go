// Package appcard serves the MCP App card: a branded view of a Secret
// Handoff tool call that hosts with the MCP Apps extension
// (io.modelcontextprotocol/ui, spec 2026-01-26) draw in the chat. The card
// shows only the tool's arguments and result text. It has no input field and
// no network access, because a host can read an app's frame and messages; the
// secret is typed only on the local fill page.
package appcard

import (
	"context"
	_ "embed"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// URI names the card resource. MIMEType is the MCP Apps HTML profile.
const (
	URI      = "ui://secrethandoff/card.html"
	MIMEType = "text/html;profile=mcp-app"
)

//go:embed card.html
var html string

// ToolMeta links a tool to the card. Hosts without MCP Apps ignore it.
func ToolMeta() mcp.Meta {
	return mcp.Meta{"ui": map[string]any{"resourceUri": URI}}
}

// Register adds the card resource to the server.
func Register(server *mcp.Server) {
	server.AddResource(&mcp.Resource{
		URI:         URI,
		Name:        "secrethandoff-card",
		Title:       "Secret Handoff request card",
		Description: "Shows a Secret Handoff request in the chat. The secret itself is typed only on the local page.",
		MIMEType:    MIMEType,
	}, func(context.Context, *mcp.ReadResourceRequest) (*mcp.ReadResourceResult, error) {
		return &mcp.ReadResourceResult{Contents: []*mcp.ResourceContents{{
			URI:      URI,
			MIMEType: MIMEType,
			Text:     html,
			// No connectDomains or resourceDomains: the card makes no requests.
			Meta: mcp.Meta{"ui": map[string]any{"prefersBorder": false}},
		}}}, nil
	})
}
