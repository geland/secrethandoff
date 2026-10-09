//go:build unix

package main

import (
	"strings"
	"testing"
	"time"
)

// TestRunWithSecretTimeoutWithChildProcess reproduces a command such as
// "aws ecs execute-command", whose own child process keeps the output pipes
// open. At the time limit the whole process group must stop, and the result
// must hold the output so far.
func TestRunWithSecretTimeoutWithChildProcess(t *testing.T) {
	f := newFixture(t)
	f.fillSecret("TOKEN")
	f.h.set("approve", "")
	args := map[string]any{
		"command":         []string{"sh", "-c", "sleep 60 & echo started; echo warming up >&2; sleep 60"},
		"secrets":         []string{"TOKEN:MY_TOKEN"},
		"timeout_seconds": 1,
	}
	start := time.Now()
	out, isErr := f.call("run_with_secret", args)
	if took := time.Since(start); took > 15*time.Second {
		t.Fatalf("run_with_secret returned after %s, not near its 1 s limit", took)
	}
	for _, want := range []string{"did not finish within 1 seconds", "started", "warming up", "standard input is empty"} {
		if !isErr || !strings.Contains(out, want) {
			t.Fatalf("missing %q in: %s", want, out)
		}
	}
	f.assertNoLeak()
}
