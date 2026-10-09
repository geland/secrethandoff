package main

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"mime"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"secrethandoff.com/cli/internal/policy"
	"secrethandoff.com/cli/internal/secrets"
)

var secretRef = regexp.MustCompile(`\{\{secret:([A-Za-z][A-Za-z0-9_]{0,63})\}\}`)

const (
	maxResponseRead = 1 << 20
	maxResponseText = 32 * 1024
	maxRedirects    = 5
)

// echoHosts return the request back to the caller, so a credential sent to
// them comes back to the agent (threat model T-27).
var echoHosts = map[string]bool{
	"httpbin.org": true, "www.httpbin.org": true, "postman-echo.com": true, "echo.hoppscotch.io": true,
	"webhook.site": true, "requestbin.com": true, "reqbin.com": true, "httpbingo.org": true,
}

var blockedHeaders = map[string]bool{"host": true, "content-length": true, "transfer-encoding": true, "connection": true, "proxy-authorization": true, "proxy-connection": true}

type httpInput struct {
	Method         string            `json:"method" jsonschema:"HTTP method, for example GET or POST."`
	URL            string            `json:"url" jsonschema:"An https URL. {{secret:NAME}} may appear only in the query."`
	Headers        map[string]string `json:"headers,omitempty" jsonschema:"Request headers. Values may contain {{secret:NAME}}, for example Authorization: Bearer {{secret:STRIPE_KEY}}."`
	Body           string            `json:"body,omitempty" jsonschema:"Request body as text. May contain {{secret:NAME}}."`
	TimeoutSeconds int               `json:"timeout_seconds,omitempty" jsonschema:"1 to 120 seconds. Default 30."`
}

// newHTTPClient builds the client for http_request. Tests pass a TLS
// configuration that trusts their test server.
func newHTTPClient(tlsConfig *tls.Config) *http.Client {
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsConfig
	tr.ResponseHeaderTimeout = 60 * time.Second
	return &http.Client{Transport: tr}
}

func addHTTPTool(server *mcp.Server, s *session) {
	mcp.AddTool(server, &mcp.Tool{
		Name: "http_request",
		Description: "Send an HTTPS request that uses one or more secrets by name, written as {{secret:NAME}} in a header, the URL query, or the body. " +
			"The binary checks each secret's policy, sends the request, and returns the response with every secret value removed. " +
			"In the URL query and in a form body (Content-Type application/x-www-form-urlencoded), the value is URL-encoded; in a JSON body, it is JSON-escaped, so write {{secret:NAME}} inside the quotes. " +
			"The request must use at least one secret.",
		Annotations: &mcp.ToolAnnotations{OpenWorldHint: ptr(true)},
	}, s.httpRequest)
}

func (s *session) httpRequest(ctx context.Context, _ *mcp.CallToolRequest, in httpInput) (*mcp.CallToolResult, any, error) {
	method := strings.ToUpper(strings.TrimSpace(in.Method))
	timeout := 30 * time.Second
	if in.TimeoutSeconds != 0 {
		if in.TimeoutSeconds < 1 || in.TimeoutSeconds > 120 {
			return s.text(true, "timeout_seconds must be 1 to 120."), nil, nil
		}
		timeout = time.Duration(in.TimeoutSeconds) * time.Second
	}

	// Parse the URL with references replaced, to check that references sit
	// only in the query.
	probe := secretRef.ReplaceAllString(in.URL, "SECRETREF")
	u, err := url.Parse(probe)
	if err != nil || u.Host == "" {
		return s.text(true, "Invalid URL."), nil, nil
	}
	if strings.Contains(u.Scheme+u.Host+u.Path+u.Fragment, "SECRETREF") {
		return s.text(true, "{{secret:NAME}} may appear only in the URL query, not in the host or path."), nil, nil
	}
	if echoHosts[strings.ToLower(u.Hostname())] {
		return s.text(true, "%s returns requests to the caller, so it would return the secret. Use a different host.", u.Hostname()), nil, nil
	}

	names := map[string]bool{}
	collect := func(s string) {
		for _, m := range secretRef.FindAllStringSubmatch(s, -1) {
			names[m[1]] = true
		}
	}
	collect(in.URL)
	collect(in.Body)
	for k, v := range in.Headers {
		if secretRef.MatchString(k) {
			return s.text(true, "{{secret:NAME}} may not appear in a header name."), nil, nil
		}
		if blockedHeaders[strings.ToLower(k)] {
			return s.text(true, "The header %s cannot be set.", k), nil, nil
		}
		collect(v)
	}
	if len(names) == 0 {
		return s.text(true, "This request uses no secret. http_request sends only requests that use a secret; use your own tools for other requests."), nil, nil
	}

	// Check every policy before any value is read.
	policies := map[string]policy.Policy{}
	for name := range names {
		if err := s.store.Use(name, func(_ []byte, p policy.Policy) error {
			policies[name] = p
			return p.Allows(method, u)
		}); err != nil {
			return s.text(true, "%s: %v", name, err), nil, nil
		}
	}

	req, err := s.buildRequest(ctx, method, in, timeout)
	if err != nil {
		return s.text(true, "%v", err), nil, nil
	}
	defer req.cancel()

	client := *s.client
	redirects := 0
	client.CheckRedirect = func(next *http.Request, _ []*http.Request) error {
		redirects++
		if redirects > maxRedirects {
			return errors.New("too many redirects")
		}
		if !strings.EqualFold(next.URL.Host, u.Host) {
			return http.ErrUseLastResponse
		}
		for name, p := range policies {
			if err := p.Allows(next.Method, next.URL); err != nil {
				return fmt.Errorf("redirect: %s: %w", name, err)
			}
		}
		return nil
	}
	res, err := client.Do(req.Request)
	if err != nil {
		return s.text(true, "Request failed: %v", scrubURLError(err)), nil, nil
	}
	defer res.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(res.Body, maxResponseRead+1))
	return s.formatResponse(res, body), nil, nil
}

type builtRequest struct {
	*http.Request
	cancel context.CancelFunc
}

// buildRequest substitutes secret values. The values exist only inside the
// request object and are never formatted into text.
func (s *session) buildRequest(ctx context.Context, method string, in httpInput, timeout time.Duration) (*builtRequest, error) {
	var missing error
	substitute := func(text string, escape func(string) string) string {
		return secretRef.ReplaceAllStringFunc(text, func(ref string) string {
			name := secretRef.FindStringSubmatch(ref)[1]
			var out string
			if err := s.store.Use(name, func(v []byte, _ policy.Policy) error { out = escape(string(v)); return nil }); err != nil {
				missing = err
			}
			return out
		})
	}
	identity := func(v string) string { return v }
	rawURL := in.URL
	if i := strings.Index(rawURL, "?"); i >= 0 {
		rawURL = rawURL[:i+1] + substitute(rawURL[i+1:], url.QueryEscape)
	}
	body := substitute(in.Body, bodyEscape(in.Headers))
	ctx, cancel := context.WithTimeout(ctx, timeout)
	req, err := http.NewRequestWithContext(ctx, method, rawURL, strings.NewReader(body))
	if err != nil {
		cancel()
		return nil, errors.New("could not build the request")
	}
	for k, v := range in.Headers {
		req.Header.Set(k, substitute(v, identity))
	}
	if missing != nil {
		cancel()
		return nil, missing
	}
	if in.Body == "" {
		req.Body, req.ContentLength = http.NoBody, 0
	}
	return &builtRequest{Request: req, cancel: cancel}, nil
}

// bodyEscape picks how a secret is written into the body, from the
// Content-Type header: URL escaping for a form, JSON string escaping for
// JSON, and the raw value otherwise.
func bodyEscape(headers map[string]string) func(string) string {
	for k, v := range headers {
		if !strings.EqualFold(k, "Content-Type") {
			continue
		}
		mediaType := strings.ToLower(strings.TrimSpace(strings.Split(v, ";")[0]))
		switch {
		case mediaType == "application/x-www-form-urlencoded":
			return url.QueryEscape
		case strings.HasSuffix(mediaType, "/json") || strings.HasSuffix(mediaType, "+json"):
			return secrets.JSONEscape
		}
	}
	return func(v string) string { return v }
}

// scrubURLError drops the URL from client errors, because the query may
// hold a secret. The redactor runs on the text afterwards too.
func scrubURLError(err error) string {
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return "timed out"
	}
	return err.Error()
}

func (s *session) formatResponse(res *http.Response, body []byte) *mcp.CallToolResult {
	r := s.store.Redactor()
	var b strings.Builder
	fmt.Fprintf(&b, "HTTP %d\n", res.StatusCode)
	keys := make([]string, 0, len(res.Header))
	for k := range res.Header {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if strings.EqualFold(k, "Set-Cookie") {
			continue
		}
		fmt.Fprintf(&b, "%s: %s\n", k, strings.Join(res.Header[k], ", "))
	}
	b.WriteString("\n")
	mediaType, _, _ := mime.ParseMediaType(res.Header.Get("Content-Type"))
	textual := mediaType == "" || strings.HasPrefix(mediaType, "text/") || strings.Contains(mediaType, "json") || strings.Contains(mediaType, "xml") || strings.HasSuffix(mediaType, "+json") || mediaType == "application/x-www-form-urlencoded" || mediaType == "application/javascript"
	switch {
	case !textual:
		fmt.Fprintf(&b, "[%d bytes of %s not shown]\n", len(body), mediaType)
	case len(body) > maxResponseText:
		b.Write(body[:maxResponseText])
		fmt.Fprintf(&b, "\n[response truncated at %d bytes]\n", maxResponseText)
	default:
		b.Write(body)
	}
	if res.StatusCode >= 300 && res.StatusCode < 400 {
		b.WriteString("\n[redirect to another host not followed]\n")
	}
	out, n := r.String(b.String())
	if n > 0 {
		out += fmt.Sprintf("\n[%d secret value(s) removed from the response]\n", n)
	}
	return &mcp.CallToolResult{IsError: res.StatusCode >= 400, Content: []mcp.Content{&mcp.TextContent{Text: out}}}
}
