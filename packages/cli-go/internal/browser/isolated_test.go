package browser

import (
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
		if installed && p == "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome" {
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
	for _, want := range []string{"--user-data-dir=", "--disable-extensions", "--no-first-run", "--use-mock-keychain", "--new-window"} {
		if !strings.Contains(args, want) {
			t.Errorf("missing %s in %s", want, args)
		}
	}
	if strings.Contains(args, "--app=") || strings.Contains(args, "remote-debugging") {
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
	Close()
	if _, err := os.Stat(dir); !os.IsNotExist(err) {
		t.Fatalf("Close left the profile: %v", err)
	}
	if isolated, how := Describe(); !isolated || !strings.Contains(how, "Google Chrome") {
		t.Errorf("Describe: %v %s", isolated, how)
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
