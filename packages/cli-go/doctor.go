package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"runtime"

	"secrethandoff.com/cli/internal/browser"
	"secrethandoff.com/cli/internal/loopback"
)

type check struct {
	Name   string `json:"name"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
	// Note marks a check that reports setup state. A failed note does not
	// make doctor fail, because local mode works without it.
	Note bool `json:"note,omitempty"`
}

// runDoctor checks what local mode needs. It prints no secrets and no
// tokens, because it creates none.
func runDoctor(args []string, stdout io.Writer) int {
	asJSON := len(args) > 0 && args[0] == "--json"
	var checks []check
	add := func(name string, err error, okDetail string) {
		c := check{Name: name, OK: err == nil, Detail: okDetail}
		if err != nil {
			c.Detail = err.Error()
		}
		checks = append(checks, c)
	}
	exe, err := os.Executable()
	add("binary", err, fmt.Sprintf("%s %s on %s/%s", exe, version, runtime.GOOS, runtime.GOARCH))
	_, how := browser.Describe()
	add("browser", browser.Available(), how)
	ln, err := loopback.Listen()
	if err == nil {
		ln.Close()
	}
	add("loopback", err, "the fill page can listen on 127.0.0.1")
	for _, c := range agentClients {
		ok, detail := pluginInstalled(c)
		checks = append(checks, check{Name: c.command, OK: ok, Detail: detail, Note: true})
	}
	if dir, err := os.Getwd(); err == nil {
		ok, detail := projectHasRules(dir)
		checks = append(checks, check{Name: "rules", OK: ok, Detail: detail, Note: true})
	}

	ok := true
	for _, c := range checks {
		ok = ok && (c.OK || c.Note)
	}
	if asJSON {
		json.NewEncoder(stdout).Encode(map[string]any{"ok": ok, "version": version, "checks": checks}) //nolint:errcheck
	} else {
		for _, c := range checks {
			mark := "ok  "
			switch {
			case !c.OK && c.Note:
				mark = "note"
			case !c.OK:
				mark = "FAIL"
			}
			fmt.Fprintf(stdout, "%s %-9s %s\n", mark, c.Name, c.Detail)
		}
	}
	if !ok {
		return 1
	}
	return 0
}
