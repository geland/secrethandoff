package main

import (
	"context"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"secrethandoff.com/cli/internal/proxy"
)

func addProxyTool(server *mcp.Server, s *session) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "proxy_settings",
		Description: "Get the settings that route one command's HTTPS requests through the local secrets proxy, for tools such as curl or an SDK that cannot use http_request. " +
			"The command writes {{secret:NAME}} where the secret goes; the proxy checks the policy, adds the value, and removes it from responses. Prefer http_request when it can do the task.",
		Annotations: &mcp.ToolAnnotations{ReadOnlyHint: true},
	}, s.proxySettings)
}

func (s *session) proxySettings(context.Context, *mcp.CallToolRequest, struct{}) (*mcp.CallToolResult, any, error) {
	s.mu.Lock()
	if s.proxy == nil {
		p, err := proxy.Start(s.store, nil)
		if err != nil {
			s.mu.Unlock()
			return s.text(true, "Could not start the proxy: %v", err), nil, nil
		}
		s.proxy = p
	}
	p := s.proxy
	s.mu.Unlock()
	set, err := p.Prepare()
	if err != nil {
		return s.text(true, "%v", err), nil, nil
	}
	env := fmt.Sprintf("HTTPS_PROXY=%[1]s SSL_CERT_FILE=%[2]s CURL_CA_BUNDLE=%[2]s NODE_EXTRA_CA_CERTS=%[2]s REQUESTS_CA_BUNDLE=%[2]s", set.ProxyURL, set.CACertFile)
	return s.text(false, "Put these variables in front of one command only, never in your shell profile or the client's environment:\n%s\n\n"+
		"Example:\n%s curl -H 'Authorization: Bearer {{secret:NAME}}' https://%s/\n\n"+
		"The proxy serves only these hosts: %s. Requests to other hosts fail. "+
		"In Codex, agent commands reach the proxy only when sandbox_workspace_write.network_access is true.",
		env, env, strings.TrimPrefix(set.Hosts[0], "*."), strings.Join(set.Hosts, ", ")), nil, nil
}
