package main

// Leak suite (plan task P1-8, release gate GG-01). It runs the real binary
// as a separate process, fills a known value through the local page, and
// asserts that no encoding of the value appears in any tool result, in raw
// stdout, or in stderr.

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const leakValue = "leak-suite-Value_7Hq2Zx9Lm4Vt8Wr3"

// TestLeakHelperBrowser acts as the browser and the human. The binary runs
// it through SECRETHANDOFF_BROWSER with the page URL as its argument.
func TestLeakHelperBrowser(t *testing.T) {
	pageURL := os.Getenv("SECRETHANDOFF_HELPER_URL_ARG")
	if pageURL == "" {
		if len(os.Args) == 0 || !strings.HasPrefix(os.Args[len(os.Args)-1], "http://127.0.0.1:") {
			return
		}
		pageURL = os.Args[len(os.Args)-1]
	}
	origin, token, _ := strings.Cut(pageURL, "/r#")
	jar, _ := cookiejar.New(nil)
	c := &http.Client{Jar: jar, Timeout: 5 * time.Second}
	get, _ := http.NewRequest("GET", origin+"/api/request", nil)
	get.Header.Set("X-Secrethandoff-Token", token)
	res, err := c.Do(get)
	if err != nil {
		os.Exit(1)
	}
	var view struct {
		Kind string `json:"kind"`
	}
	json.NewDecoder(res.Body).Decode(&view)
	res.Body.Close()
	action, body := "approve", "{}"
	if view.Kind == "fill" {
		b, _ := json.Marshal(map[string]string{"value": os.Getenv("SECRETHANDOFF_LEAK_VALUE")})
		action, body = "fill", string(b)
	}
	post, _ := http.NewRequest("POST", origin+"/api/"+action, strings.NewReader(body))
	post.Header.Set("X-Secrethandoff-Token", token)
	post.Header.Set("Origin", origin)
	post.Header.Set("Content-Type", "application/json")
	if res, err := c.Do(post); err == nil {
		res.Body.Close()
	}
	os.Exit(0)
}

// TestLeakPrinter is the command that run_with_secret starts. It prints the
// secret in every encoding the redactor must catch.
func TestLeakPrinter(t *testing.T) {
	if os.Getenv("SECRETHANDOFF_LEAK_PRINTER") != "1" {
		return
	}
	v := os.Getenv("LEAK_ENV")
	fmt.Println("raw", v)
	fmt.Println("b64", base64.StdEncoding.EncodeToString([]byte(v)))
	fmt.Println("b64url", base64.RawURLEncoding.EncodeToString([]byte(v)))
	fmt.Println("basic", base64.StdEncoding.EncodeToString([]byte("user:"+v)))
	fmt.Println("hex", hex.EncodeToString([]byte(v)))
	fmt.Println("HEX", strings.ToUpper(hex.EncodeToString([]byte(v))))
	fmt.Println("url", url.QueryEscape(v))
	fmt.Fprintln(os.Stderr, "stderr", v)
	os.Exit(0)
}

func leakForms(v string) []string {
	forms := []string{v, base64.StdEncoding.EncodeToString([]byte(v)), base64.RawURLEncoding.EncodeToString([]byte(v)),
		hex.EncodeToString([]byte(v)), strings.ToUpper(hex.EncodeToString([]byte(v))), url.QueryEscape(v)}
	// The middle of base64 at any offset, as in basic authentication.
	full := base64.StdEncoding.EncodeToString([]byte("user:" + v))
	return append(forms, full[10:len(full)-6])
}

type lockedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}
func (l *lockedBuffer) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

type teeReadCloser struct {
	io.Reader
	io.Closer
}

func TestLeakSuite(t *testing.T) {
	bin := filepath.Join(t.TempDir(), "secrethandoff")
	if out, err := exec.Command("go", "build", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v\n%s", err, out)
	}
	self, _ := os.Executable()
	launcher := writeLauncher(t, filepath.Join(t.TempDir(), "launcher"), self)

	cmd := exec.Command(bin, "mcp")
	cmd.Env = append(os.Environ(),
		"SECRETHANDOFF_BROWSER="+launcher,
		"SECRETHANDOFF_LEAK_VALUE="+leakValue,
		"SECRETHANDOFF_WAIT_SECONDS=10",
		"SECRETHANDOFF_LEAK_PRINTER=1",
	)
	stderr := &lockedBuffer{}
	cmd.Stderr = stderr
	stdin, _ := cmd.StdinPipe()
	stdoutPipe, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	rawStdout := &lockedBuffer{}
	transport := &mcp.IOTransport{Reader: teeReadCloser{io.TeeReader(stdoutPipe, rawStdout), stdoutPipe}, Writer: stdin}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "leak-suite", Version: "1"}, nil).Connect(ctx, transport, nil)
	if err != nil {
		t.Fatal(err)
	}
	var results []string
	call := func(name string, args map[string]any) string {
		res, err := cs.CallTool(ctx, &mcp.CallToolParams{Name: name, Arguments: args})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		var b strings.Builder
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				b.WriteString(tc.Text)
			}
		}
		results = append(results, name+": "+b.String())
		return b.String()
	}

	pol := map[string]any{"hosts": []string{"leaktest.invalid"}}
	if out := call("request_secret", map[string]any{"name": "LEAK", "reason": "Leak suite", "policy": pol}); !strings.Contains(out, "LEAK is ready") {
		t.Fatalf("request_secret: %s", out)
	}
	call("list_secrets", nil)
	// Error paths that hold the value: a failed request with the secret in
	// the query, a header, and the body.
	call("http_request", map[string]any{"method": "POST", "url": "https://leaktest.invalid/x?k={{secret:LEAK}}",
		"headers": map[string]string{"Authorization": "Bearer {{secret:LEAK}}"}, "body": "{{secret:LEAK}}", "timeout_seconds": 5})
	call("http_request", map[string]any{"method": "GET", "url": "https://other.invalid/?k={{secret:LEAK}}"})
	call("http_request", map[string]any{"method": "GET", "url": "https://leaktest.invalid/{{secret:LEAK}}"})
	out := call("run_with_secret", map[string]any{"command": []string{self, "-test.run=^TestLeakPrinter$"}, "secrets": []string{"LEAK:LEAK_ENV"}})
	if !strings.Contains(out, "raw [REDACTED:LEAK]") {
		t.Fatalf("run_with_secret: %s", out)
	}
	call("run_with_secret", map[string]any{"command": []string{"definitely-not-a-program-xyz"}, "secrets": []string{"LEAK:LEAK_ENV"}})
	call("forget_secret", map[string]any{"name": "LEAK"})
	call("http_request", map[string]any{"method": "GET", "url": "https://leaktest.invalid/?k={{secret:LEAK}}"})

	cs.Close()
	stdin.Close()
	cmd.Wait()

	pageToken := regexp.MustCompile(`/r#[A-Za-z0-9_-]{43}`)
	for label, text := range map[string]string{"tool results": strings.Join(results, "\n"), "raw stdout": rawStdout.String(), "stderr": stderr.String()} {
		for _, form := range leakForms(leakValue) {
			if strings.Contains(text, form) {
				t.Errorf("%s contain the secret in the form %q", label, form)
			}
		}
		if pageToken.MatchString(text) {
			t.Errorf("%s contain a page link with its token", label)
		}
	}
	if len(results) < 9 {
		t.Fatalf("only %d tool calls ran", len(results))
	}
}
