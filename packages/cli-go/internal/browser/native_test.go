package browser

import (
	"os"
	"testing"
	"time"

	"secrethandoff.com/cli/internal/localpage"
	"secrethandoff.com/cli/internal/policy"
)

// Explicitly opt in: opens two synthetic requests in the real isolated
// browser, never fills them, and cleans up only this test's owned instance.
// No page link, token, captured body, or screenshot is emitted.
func TestNativeBrowserPresence(t *testing.T) {
	if os.Getenv("SH_NATIVE_BROWSER_TEST") != "1" {
		t.Skip("opt-in native browser smoke test")
	}
	if chromium() == "" || isolationOff() || os.Getenv("SECRETHANDOFF_BROWSER") != "" {
		t.Fatal("native smoke test requires an isolated Chromium browser")
	}
	defer Close()
	s, err := localpage.Start(Open)
	if err != nil {
		t.Fatal("could not start synthetic page server")
	}
	defer s.Close()
	connected := make(chan struct{}, 4)
	s.SetPagePresence(func() func() {
		release := PageConnected()
		connected <- struct{}{}
		return release
	})
	s.SetAbout(localpage.About{Client: "Synthetic browser smoke test", Version: "test", Isolated: true})
	for _, name := range []string{"SYNTHETIC_FIRST", "SYNTHETIC_SECOND"} {
		if _, err := s.NewFill(name, "Browser lifecycle test. Do not enter a credential.", policy.Policy{Hosts: []string{"example.invalid"}}, time.Minute, func([]byte) error { return nil }, nil); err != nil {
			t.Fatal("could not open synthetic page")
		}
		select {
		case <-connected:
		case <-time.After(20 * time.Second):
			t.Fatal("native page did not connect its presence socket")
		}
	}
	iso.mu.Lock()
	dir, pages := iso.dir, iso.pages
	iso.mu.Unlock()
	if pages != 2 {
		t.Fatal("native tabs did not hold the browser alive")
	}
	// Transport disconnect uses the same retirement path as closing the tabs.
	s.Close()
	deadline := time.Now().Add(browserIdleGrace + 5*time.Second)
	for time.Now().Before(deadline) {
		iso.mu.Lock()
		retired := iso.dir == ""
		iso.mu.Unlock()
		if retired {
			if _, err := os.Stat(dir); !os.IsNotExist(err) {
				t.Fatal("native profile was retained")
			}
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatal("native browser was not retired after its pages disconnected")
}
