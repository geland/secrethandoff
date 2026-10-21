//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"testing"
)

// The browser launcher executes a program directly, so Windows needs an
// executable rather than a batch file. Keep the private URL only in memory.
func writeLauncher(t *testing.T, path, self string) string {
	t.Helper()
	source := path + ".go"
	script := fmt.Sprintf(`package main
import ("os"; "os/exec")
func main() {
 if len(os.Args) != 2 { os.Exit(1) }
 cmd := exec.Command(%q, "-test.run=^TestLeakHelperBrowser$")
 cmd.Env = append(os.Environ(), "SECRETHANDOFF_HELPER_URL_ARG="+os.Args[1])
 if cmd.Run() != nil { os.Exit(1) }
}
`, self)
	if err := os.WriteFile(source, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	path += ".exe"
	if _, err := exec.Command("go", "build", "-o", path, source).CombinedOutput(); err != nil {
		t.Fatal("could not build the Windows leak-test browser launcher")
	}
	return path
}
