// Package browser opens a URL without a shell: in an isolated window of a
// Chromium-family browser when one is installed, else in the default browser.
package browser

import (
	"errors"
	"os"
	"os/exec"
	"runtime"
)

// ErrNoDisplay means local mode cannot show a page on this computer.
var ErrNoDisplay = errors.New("no display: local mode cannot open a browser here")

// Available reports whether Open can show a page, and why not.
func Available() error {
	if os.Getenv("SECRETHANDOFF_NO_BROWSER") != "" {
		return ErrNoDisplay
	}
	// An explicit launcher is trusted to know how to show the page.
	if os.Getenv("SECRETHANDOFF_BROWSER") != "" {
		return nil
	}
	// Over SSH, a browser would open on a screen the user cannot see.
	if os.Getenv("SSH_CONNECTION") != "" || os.Getenv("SSH_TTY") != "" {
		return ErrNoDisplay
	}
	switch runtime.GOOS {
	case "darwin", "windows":
		return nil
	default:
		if os.Getenv("DISPLAY") == "" && os.Getenv("WAYLAND_DISPLAY") == "" {
			return ErrNoDisplay
		}
		if _, err := exec.LookPath("xdg-open"); err != nil {
			return ErrNoDisplay
		}
		return nil
	}
}

// Open shows url. It passes url as one argument, never through a shell, and
// writes nothing to stdout or stderr. The isolated window is the default;
// SECRETHANDOFF_BROWSER and SECRETHANDOFF_ISOLATED_BROWSER=0 change it.
func Open(url string) error {
	if err := Available(); err != nil {
		return err
	}
	var cmd *exec.Cmd
	if custom := os.Getenv("SECRETHANDOFF_BROWSER"); custom != "" {
		// SECRETHANDOFF_BROWSER names one program, run with the URL as its
		// only argument. It is not parsed by a shell.
		cmd = exec.Command(custom, url)
	} else if bin := chromium(); bin != "" && !isolationOff() {
		return openIsolated(bin, url)
	} else {
		cmd = defaultCommand(url)
	}
	cmd.Stdout, cmd.Stderr = nil, nil
	if err := cmd.Start(); err != nil {
		return err
	}
	go cmd.Wait() //nolint:errcheck // the launcher exits on its own
	return nil
}

func defaultCommand(url string) *exec.Cmd {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "darwin":
		cmd = exec.Command("open", url)
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", url)
	default:
		cmd = exec.Command("xdg-open", url)
	}
	return cmd
}
