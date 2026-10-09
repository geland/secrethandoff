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
	mu    sync.Mutex
	dir   string
	procs []*os.Process
}

var iso isolatedState

// Test seams.
var (
	statFile = os.Stat
	lookPath = exec.LookPath
	goos     = runtime.GOOS
	startCmd = func(cmd *exec.Cmd) error { return cmd.Start() }
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
		"--window-size=760,960",
		"--new-window",
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
		iso.dir = dir
	}
	cmd := exec.Command(bin, isolatedArgs(iso.dir, url)...)
	cmd.Stdout, cmd.Stderr = nil, nil
	if err := startCmd(cmd); err != nil {
		return err
	}
	if cmd.Process != nil {
		iso.procs = append(iso.procs, cmd.Process)
		go cmd.Wait() //nolint:errcheck // a later launch hands its URL to the first and exits
	}
	return nil
}

// Close stops the isolated browser and deletes its temporary profile. The
// session calls it when it ends.
func Close() {
	iso.mu.Lock()
	defer iso.mu.Unlock()
	for _, p := range iso.procs {
		p.Kill() //nolint:errcheck // it may have exited already
	}
	iso.procs = nil
	if iso.dir != "" {
		// The browser can still be writing for a moment after the kill.
		for i := 0; i < 5; i++ {
			if os.RemoveAll(iso.dir) == nil {
				break
			}
			time.Sleep(200 * time.Millisecond)
		}
		iso.dir = ""
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
