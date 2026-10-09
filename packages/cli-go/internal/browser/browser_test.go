package browser

import "testing"

func TestNoBrowserOverride(t *testing.T) {
	t.Setenv("SECRETHANDOFF_NO_BROWSER", "1")
	if Available() != ErrNoDisplay || Open("http://127.0.0.1:1/") != ErrNoDisplay {
		t.Fatal("SECRETHANDOFF_NO_BROWSER must disable the browser")
	}
}

func TestSSHMeansNoDisplay(t *testing.T) {
	t.Setenv("SECRETHANDOFF_NO_BROWSER", "")
	t.Setenv("SSH_CONNECTION", "10.0.0.1 22 10.0.0.2 22")
	if Available() != ErrNoDisplay {
		t.Fatal("an SSH session must count as no display")
	}
}

func TestCustomLauncherOverridesSSH(t *testing.T) {
	t.Setenv("SECRETHANDOFF_NO_BROWSER", "")
	t.Setenv("SSH_CONNECTION", "10.0.0.1 22 10.0.0.2 22")
	t.Setenv("SECRETHANDOFF_BROWSER", "/bin/true")
	if Available() != nil {
		t.Fatal("an explicit launcher must make the browser available")
	}
}
