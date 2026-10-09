package main

import (
	"bytes"
	"strings"
	"testing"
)

func TestRunCommands(t *testing.T) {
	cases := []struct {
		args       []string
		code       int
		wantStdout string
		wantStderr string
	}{
		{[]string{"version"}, 0, version + "\n", ""},
		{[]string{"help"}, 0, "secrethandoff mcp", ""},
		{nil, 2, "", "Usage:"},
		{[]string{"nope"}, 2, "", `unknown command "nope"`},
	}
	for _, c := range cases {
		var out, errOut bytes.Buffer
		if code := run(c.args, &out, &errOut); code != c.code {
			t.Errorf("run(%q) = %d, want %d", c.args, code, c.code)
		}
		if !strings.Contains(out.String(), c.wantStdout) || !strings.Contains(errOut.String(), c.wantStderr) {
			t.Errorf("run(%q): stdout %q, stderr %q", c.args, out.String(), errOut.String())
		}
	}
}
