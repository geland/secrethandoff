package browser

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"time"
)

// The isolated window (threat model T-55): a Chromium-family browser started
// with a temporary profile for this session. The profile has no extensions,
// so an AI browser extension in the user's own profile cannot read the fill
// page. The window is a normal one, so the address bar shows 127.0.0.1.

// IsolationEnv turns the isolated window off when set to 0, false, or off.
const IsolationEnv = "SECRETHANDOFF_ISOLATED_BROWSER"

type isolatedState struct {
	mu         sync.Mutex
	dir        string
	procs      map[*os.Process]<-chan struct{}
	pages      int
	generation uint64
	idle       *time.Timer
}

var iso isolatedState

// Allow reloads, connection retries, and newly opened tabs to attach before
// retiring a browser whose last Secret Handoff page has gone away.
const browserIdleGrace = 30 * time.Second

// PageConnected keeps the isolated browser alive while a local page has its
// authenticated presence stream open. The returned function releases it once.
// This carries no request token or secret and never changes request state.
func PageConnected() func() {
	iso.mu.Lock()
	defer iso.mu.Unlock()
	if iso.dir == "" {
		return func() {}
	}
	iso.stopIdleLocked()
	iso.pages++
	generation := iso.generation
	var once sync.Once
	return func() {
		once.Do(func() {
			iso.mu.Lock()
			defer iso.mu.Unlock()
			if iso.generation != generation {
				return
			}
			iso.pages--
			if iso.pages == 0 {
				iso.scheduleIdleLocked()
			}
		})
	}
}

func (s *isolatedState) stopIdleLocked() {
	if s.idle != nil {
		s.idle.Stop()
		s.idle = nil
	}
}

func (s *isolatedState) scheduleIdleLocked() {
	s.stopIdleLocked()
	generation := s.generation
	// Compare the timer as well as the generation: Stop can race a callback
	// already waiting for the mutex, including during a new launch.
	var timer *time.Timer
	timer = afterIdle(browserIdleGrace, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		if s.generation == generation && s.idle == timer && s.pages == 0 {
			s.closeLocked()
		}
	})
	s.idle = timer
}

// Test seams.
var (
	statFile  = os.Stat
	lookPath  = exec.LookPath
	goos      = runtime.GOOS
	startCmd  = func(cmd *exec.Cmd) error { return cmd.Start() }
	afterIdle = time.AfterFunc
)

func isolationOff() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(IsolationEnv))) {
	case "0", "false", "off", "no":
		return true
	}
	return false
}

// chromium returns the path of an installed Chromium-family browser, or "".
func chromium() string {
	switch goos {
	case "darwin":
		var roots = []string{"/Applications"}
		if home, err := os.UserHomeDir(); err == nil {
			roots = append(roots, filepath.Join(home, "Applications"))
		}
		for _, root := range roots {
			for _, app := range []string{
				"Google Chrome.app/Contents/MacOS/Google Chrome",
				"Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
				"Brave Browser.app/Contents/MacOS/Brave Browser",
				"Chromium.app/Contents/MacOS/Chromium",
			} {
				if p := filepath.Join(root, app); isFile(p) {
					return p
				}
			}
		}
	case "windows":
		for _, base := range []string{os.Getenv("ProgramFiles"), os.Getenv("ProgramFiles(x86)"), os.Getenv("LOCALAPPDATA")} {
			if base == "" {
				continue
			}
			for _, exe := range []string{
				`Google\Chrome\Application\chrome.exe`,
				`Microsoft\Edge\Application\msedge.exe`,
				`BraveSoftware\Brave-Browser\Application\brave.exe`,
			} {
				if p := filepath.Join(base, exe); isFile(p) {
					return p
				}
			}
		}
	default:
		for _, name := range []string{"google-chrome", "google-chrome-stable", "microsoft-edge", "brave-browser", "chromium", "chromium-browser"} {
			if p, err := lookPath(name); err == nil {
				return p
			}
		}
	}
	return ""
}

func isFile(p string) bool {
	st, err := statFile(p)
	return err == nil && !st.IsDir()
}

// isolatedArgs are the browser arguments for one fill page. dir is the
// session's temporary profile.
func isolatedArgs(dir, url string) []string {
	args := []string{
		"--user-data-dir=" + dir,
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-extensions",
		"--disable-sync",
		"--disable-background-mode",
		"--incognito",
		"--window-size=760,960",
	}
	switch goos {
	case "darwin":
		// The throwaway profile never reads or writes the user's keychain.
		args = append(args, "--use-mock-keychain")
	case "linux":
		args = append(args, "--password-store=basic")
	}
	return append(args, url)
}

func openIsolated(bin, url string) error {
	iso.mu.Lock()
	defer iso.mu.Unlock()
	if iso.dir == "" {
		dir, err := os.MkdirTemp("", "secrethandoff-browser-")
		if err != nil {
			return err
		}
		// Only fixed preferences go on disk. Never write URLs, tokens, or
		// values. Incognito also prevents restoring handoff tabs from disk.
		if err := prepareProfile(dir); err != nil {
			os.RemoveAll(dir) //nolint:errcheck
			return err
		}
		iso.dir = dir
		iso.generation++
	}
	iso.stopIdleLocked()
	cmd := exec.Command(bin, isolatedArgs(iso.dir, url)...)
	cmd.Stdout, cmd.Stderr = nil, nil
	if err := startCmd(cmd); err != nil {
		if iso.pages == 0 {
			iso.closeLocked()
		}
		return err
	}
	if cmd.Process != nil {
		if iso.procs == nil {
			iso.procs = make(map[*os.Process]<-chan struct{})
		}
		done := make(chan struct{})
		iso.procs[cmd.Process] = done
		go func() {
			cmd.Wait() //nolint:errcheck // subsequent launches hand off the URL and exit
			close(done)
			iso.mu.Lock()
			delete(iso.procs, cmd.Process)
			iso.mu.Unlock()
		}()
	}
	// Retire a failed/abandoned startup too, even if its page never connects.
	if iso.pages == 0 {
		iso.scheduleIdleLocked()
	}
	return nil
}

func prepareProfile(dir string) error {
	profile := filepath.Join(dir, "Default")
	if err := os.Mkdir(profile, 0700); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(profile, "Preferences"), []byte(`{"credentials_enable_service":false,"credentials_enable_autosignin":false,"profile":{"password_manager_enabled":false}}`), 0600)
}

// Close stops the isolated browser and deletes its temporary profile. The
// session calls it when it ends.
func Close() {
	iso.mu.Lock()
	defer iso.mu.Unlock()
	iso.closeLocked()
}

func (s *isolatedState) closeLocked() {
	s.stopIdleLocked()
	s.generation++
	s.pages = 0
	for p := range s.procs {
		p.Kill() //nolint:errcheck // it may have exited already
	}
	// Reap tracked launchers before removing their profile. One shared bound
	// keeps shutdown responsive even when many launcher processes were used.
	deadline := time.NewTimer(3 * time.Second)
	defer deadline.Stop()
	for _, done := range s.procs {
		select {
		case <-done:
		case <-deadline.C:
			return // keep the profile if a process may still be writing it
		}
	}
	s.procs = nil
	if s.dir != "" {
		// The browser can still be writing for a moment after the kill.
		for i := 0; i < 5; i++ {
			if os.RemoveAll(s.dir) == nil {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		s.dir = ""
	}
}

// Describe says how Open shows pages: in the isolated window of which
// browser, or in another browser.
func Describe() (isolated bool, detail string) {
	if os.Getenv("SECRETHANDOFF_BROWSER") != "" {
		return false, "opens fill pages with SECRETHANDOFF_BROWSER"
	}
	if isolationOff() {
		return false, "opens fill pages in the default browser (" + IsolationEnv + " is off)"
	}
	if bin := chromium(); bin != "" {
		return true, "opens fill pages in a separate " + browserName(bin) + " window with a temporary profile and no extensions"
	}
	return false, "opens fill pages in the default browser (no Chrome, Edge, Brave, or Chromium found for an isolated window)"
}

func browserName(bin string) string {
	b := strings.ToLower(filepath.Base(bin))
	switch {
	case strings.Contains(b, "edge"):
		return "Microsoft Edge"
	case strings.Contains(b, "brave"):
		return "Brave"
	case strings.Contains(b, "chromium"):
		return "Chromium"
	default:
		return "Google Chrome"
	}
}
