package main

import (
	"errors"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"

	"secrethandoff.com/cli/internal/browser"
	"secrethandoff.com/cli/internal/localpage"
	"secrethandoff.com/cli/internal/proxy"
	"secrethandoff.com/cli/internal/secrets"
)

// session holds the state of one MCP session. Secrets end with the session.
type session struct {
	store     *secrets.Store
	open      func(url string) error
	available func() error
	client    *http.Client
	relayURL  string
	// wait bounds how long one tool call waits for the human. Some agent
	// clients time out tool calls after 60 seconds.
	wait time.Duration

	pagesOnce sync.Once
	pages     *localpage.Server
	pagesErr  error

	// agentMu guards agent, the client's name and version for the local
	// page. It is separate from mu, because pageServer runs under mu.
	agentMu sync.Mutex
	agent   string

	mu        sync.Mutex
	proxy     *proxy.Proxy
	fills     map[string]*fillRequest
	approvals map[string]*localpage.Request
	remotes   map[string]*remoteRequest
}

type fillRequest struct {
	req        *localpage.Request
	policyHash string
}

func newSession() *session {
	wait := 45 * time.Second
	if v, err := strconv.Atoi(os.Getenv("SECRETHANDOFF_WAIT_SECONDS")); err == nil && v > 0 && v <= 600 {
		wait = time.Duration(v) * time.Second
	}
	return &session{
		store:     secrets.NewStore(),
		open:      browser.Open,
		available: browser.Available,
		client:    newHTTPClient(nil),
		relayURL:  relayURLFromEnv(),
		wait:      wait,
		fills:     map[string]*fillRequest{},
		approvals: map[string]*localpage.Request{},
		remotes:   map[string]*remoteRequest{},
	}
}

// pageServer starts the loopback server on first use.
func (s *session) pageServer() (*localpage.Server, error) {
	s.pagesOnce.Do(func() {
		if err := s.available(); err != nil {
			s.pagesErr = errNoDisplay
			return
		}
		s.pages, s.pagesErr = localpage.Start(s.open)
		if s.pagesErr == nil {
			s.agentMu.Lock()
			isolated, _ := browser.Describe()
			s.pages.SetAbout(localpage.About{Client: s.agent, Version: version, Isolated: isolated})
			s.agentMu.Unlock()
		}
	})
	if s.pagesErr != nil {
		return nil, s.pagesErr
	}
	return s.pages, nil
}

// close erases every secret, stops the page server, and closes the isolated
// browser window with its temporary profile.
func (s *session) close() {
	s.store.ForgetAll()
	s.mu.Lock()
	names := make([]string, 0, len(s.remotes))
	for name := range s.remotes {
		names = append(names, name)
	}
	s.mu.Unlock()
	for _, name := range names {
		s.dropRemote(name)
	}
	if s.pages != nil {
		s.pages.Close()
	}
	browser.Close()
	s.mu.Lock()
	if s.proxy != nil {
		s.proxy.Close()
	}
	s.mu.Unlock()
}

var errNoDisplay = errors.New("local mode needs a browser on this computer, and none is available (SSH session, no display, or SECRETHANDOFF_NO_BROWSER is set). Ask the user to run the agent on a computer with a browser")
