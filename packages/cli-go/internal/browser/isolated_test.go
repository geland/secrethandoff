package browser

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

type fakeInfo struct{ fs.FileInfo }

func (fakeInfo) IsDir() bool { return false }

// fakeMac makes Chrome look installed and records each launch instead of
// starting a browser.
func fakeMac(t *testing.T, installed bool) *[][]string {
	t.Helper()
	launches := &[][]string{}
	oldStat, oldGOOS, oldStart := statFile, goos, startCmd
	t.Cleanup(func() { statFile, goos, startCmd = oldStat, oldGOOS, oldStart; Close() })
	goos = "darwin"
	statFile = func(p string) (fs.FileInfo, error) {
		if installed && p == filepath.Join("/Applications", "Google Chrome.app/Contents/MacOS/Google Chrome") {
			return fakeInfo{}, nil
		}
		return nil, errors.New("not found")
	}
	startCmd = func(cmd *exec.Cmd) error {
		*launches = append(*launches, cmd.Args)
		return nil
	}
	t.Setenv("SECRETHANDOFF_NO_BROWSER", "")
	t.Setenv("SECRETHANDOFF_BROWSER", "")
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("SSH_TTY", "")
	t.Setenv(IsolationEnv, "")
	return launches
}

func TestOpenUsesAnIsolatedProfile(t *testing.T) {
	if testingGOOS() != "darwin" {
		t.Skip("Available() follows the real OS")
	}
	launches := fakeMac(t, true)
	for _, u := range []string{"http://127.0.0.1:1/r#a", "http://127.0.0.1:1/r#b"} {
		if err := Open(u); err != nil {
			t.Fatal(err)
		}
	}
	if len(*launches) != 2 {
		t.Fatalf("launches: %v", *launches)
	}
	first, second := (*launches)[0], (*launches)[1]
	args := strings.Join(first, " ")
	for _, want := range []string{"--user-data-dir=", "--disable-extensions", "--no-first-run", "--use-mock-keychain", "--incognito", "--disable-background-mode"} {
		if !strings.Contains(args, want) {
			t.Errorf("missing %s in %s", want, args)
		}
	}
	if strings.Contains(args, "--app=") || strings.Contains(args, "remote-debugging") || strings.Contains(args, "--new-window") {
		t.Errorf("unwanted flag in %s", args)
	}
	if first[len(first)-1] != "http://127.0.0.1:1/r#a" {
		t.Errorf("the URL must be the last argument: %v", first)
	}
	// One temporary profile per session.
	if first[1] != second[1] || !strings.HasPrefix(first[1], "--user-data-dir=") {
		t.Errorf("profiles differ: %s %s", first[1], second[1])
	}
	dir := strings.TrimPrefix(first[1], "--user-data-dir=")
	if st, err := os.Stat(dir); err != nil || !st.IsDir() || !strings.Contains(filepath.Base(dir), "secrethandoff-browser-") {
		t.Fatalf("profile dir %s: %v", dir, err)
	}
	b, err := os.ReadFile(filepath.Join(dir, "Default", "Preferences"))
	if err != nil {
		t.Fatal(err)
	}
	var prefs struct {
		Save       bool `json:"credentials_enable_service"`
		Autosignin bool `json:"credentials_enable_autosignin"`
		Profile    struct {
			Passwords bool `json:"password_manager_enabled"`
		} `json:"profile"`
	}
	if err := json.Unmarshal(b, &prefs); err != nil {
		t.Fatal(err)
	}
	if prefs.Save || prefs.Autosignin || prefs.Profile.Passwords || !strings.Contains(string(b), `"credentials_enable_service":false`) {
		t.Fatal("profile must disable password saving and autosignin")
	}
	if st, err := os.Stat(filepath.Join(dir, "Default", "Preferences")); err != nil || st.Mode().Perm() != 0600 {
		t.Fatal("profile preferences must be private")
	}
	Close()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("Close left the profile: %v", err)
	}
	if isolated, how := Describe(); !isolated || !strings.Contains(how, "Google Chrome") {
		t.Errorf("Describe: %v %s", isolated, how)
	}
}

// Run idle callbacks deterministically, including stopped callbacks which have
// already started and are waiting for the browser mutex.
func captureIdle(t *testing.T) *[]func() {
	t.Helper()
	callbacks := &[]func(){}
	old := afterIdle
	t.Cleanup(func() { Close(); afterIdle = old })
	afterIdle = func(delay time.Duration, f func()) *time.Timer {
		if delay != browserIdleGrace {
			t.Fatal("unexpected browser grace period")
		}
		*callbacks = append(*callbacks, f)
		return time.NewTimer(time.Hour)
	}
	return callbacks
}

func TestIdleRetiresOnlyAfterLastPageAndAllowsReopen(t *testing.T) {
	launches := fakeMac(t, true)
	callbacks := captureIdle(t)
	if err := openIsolated("fake-browser", "http://127.0.0.1:1/"); err != nil {
		t.Fatal(err)
	}
	dir := iso.dir
	startup := (*callbacks)[0]
	first, second := PageConnected(), PageConnected()
	startup()
	first()
	first() // release is idempotent
	if len(*callbacks) != 1 || iso.pages != 1 {
		t.Fatal("another page still owns the browser")
	}
	second()
	idle := (*callbacks)[1]
	reloaded := PageConnected()
	idle() // a reload supersedes even a callback already running
	if iso.dir != dir {
		t.Fatal("reload retired the browser")
	}
	reloaded()
	(*callbacks)[2]()
	if iso.dir != "" {
		t.Fatal("last page did not retire the browser")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("idle profile was retained")
	}
	if err := openIsolated("fake-browser", "http://127.0.0.1:1/"); err != nil {
		t.Fatal(err)
	}
	if iso.dir == dir || len(*launches) != 2 {
		t.Fatal("reopen needs a fresh private profile")
	}
	idle()
	reloaded()
	if iso.dir == "" || iso.pages != 0 {
		t.Fatal("old callbacks affected a new profile")
	}
}

func TestNewLaunchSupersedesIdleCallback(t *testing.T) {
	fakeMac(t, true)
	callbacks := captureIdle(t)
	if err := openIsolated("fake-browser", "http://127.0.0.1:1/"); err != nil {
		t.Fatal(err)
	}
	dir := iso.dir
	if err := openIsolated("fake-browser", "http://127.0.0.1:1/"); err != nil {
		t.Fatal(err)
	}
	(*callbacks)[0]()
	if iso.dir != dir {
		t.Fatal("stopped startup timer killed a new launch")
	}
	(*callbacks)[1]()
	if iso.dir != "" {
		t.Fatal("abandoned startup did not retire")
	}
}

func TestFailedLaunchRemovesUnusedProfile(t *testing.T) {
	fakeMac(t, true)
	var profile string
	startCmd = func(cmd *exec.Cmd) error {
		profile = strings.TrimPrefix(cmd.Args[1], "--user-data-dir=")
		return errors.New("launch failed")
	}
	if err := openIsolated("fake-browser", "http://127.0.0.1:1/"); err == nil {
		t.Fatal("launch succeeded")
	}
	if iso.dir != "" {
		t.Fatal("failed launch retained its profile")
	}
	if _, err := os.Stat(profile); !os.IsNotExist(err) {
		t.Fatal("failed launch left files")
	}
}

func TestIsolatedBrowserChild(t *testing.T) {
	if os.Getenv("SH_BROWSER_TEST_CHILD") == "1" {
		time.Sleep(time.Hour)
	}
}

func TestIdleCleanupReapsOwnedProcess(t *testing.T) {
	fakeMac(t, true)
	callbacks := captureIdle(t)
	startCmd = func(cmd *exec.Cmd) error {
		cmd.Path = os.Args[0]
		cmd.Err = nil // replace exec.Command's failed lookup of the fake browser
		cmd.Args = []string{os.Args[0], "-test.run=^TestIsolatedBrowserChild$"}
		cmd.Env = append(os.Environ(), "SH_BROWSER_TEST_CHILD=1")
		return cmd.Start()
	}
	if err := openIsolated("fake-browser", "http://127.0.0.1:1/"); err != nil {
		t.Fatal("could not start test child")
	}
	dir := iso.dir
	var done <-chan struct{}
	for _, d := range iso.procs {
		done = d
	}
	if done == nil {
		t.Fatal("child was not tracked")
	}
	(*callbacks)[0]()
	select {
	case <-done:
	default:
		t.Fatal("cleanup did not reap its child")
	}
	if iso.dir != "" {
		t.Fatal("profile retained after process exited")
	}
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatal("profile files retained")
	}
}

func TestOptOutAndFallback(t *testing.T) {
	launches := fakeMac(t, true)
	t.Setenv(IsolationEnv, "0")
	if isolated, how := Describe(); isolated || !strings.Contains(how, IsolationEnv) {
		t.Errorf("opt-out Describe: %v %s", isolated, how)
	}
	if bin := chromium(); bin == "" || !isolationOff() {
		t.Fatal("opt-out must keep detection but turn isolation off")
	}
	t.Setenv(IsolationEnv, "")
	fakeMac(t, false)
	if isolated, how := Describe(); isolated || !strings.Contains(how, "default browser") {
		t.Errorf("no Chromium Describe: %v %s", isolated, how)
	}
	if len(*launches) != 0 {
		t.Errorf("Describe must not launch: %v", *launches)
	}
}

func TestCloseWithoutLaunchIsSafe(t *testing.T) {
	done := make(chan struct{})
	go func() { Close(); close(done) }()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Close blocked")
	}
}

func testingGOOS() string { return oldGOOS }

var oldGOOS = goos
