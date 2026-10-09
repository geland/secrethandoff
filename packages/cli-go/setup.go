package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// defaultMarketplace is the public integrations repository. Both Claude Code
// and Codex accept a GitHub owner/repo or a local folder as the source.
const defaultMarketplace = "geland/secrethandoff-integrations"

const pluginID = "secrethandoff@secrethandoff"

// agentClient is an agent CLI that can install the plugin.
type agentClient struct {
	name    string     // display name
	command string     // executable name on PATH
	steps   [][]string // arguments for each install step; %s is the marketplace
	list    []string   // arguments that print installed plugins as JSON
}

var agentClients = []agentClient{
	{
		name:    "Claude Code",
		command: "claude",
		steps:   [][]string{{"plugin", "marketplace", "add", "%s"}, {"plugin", "install", pluginID}},
		list:    []string{"plugin", "list", "--json"},
	},
	{
		name:    "Codex",
		command: "codex",
		steps:   [][]string{{"plugin", "marketplace", "add", "%s"}, {"plugin", "add", pluginID}},
		list:    []string{"plugin", "list", "--json"},
	},
}

// Test seams: finding and running an agent CLI.
var (
	lookPath  = exec.LookPath
	runClient = func(ctx context.Context, path string, args ...string) ([]byte, error) {
		return exec.CommandContext(ctx, path, args...).CombinedOutput()
	}
)

// setupClients connects available agent CLIs and verifies that the plugin is
// enabled. An already-enabled plugin is left alone on repeat setup.
func setupClients(marketplace string, dryRun bool, stdout, stderr io.Writer) int {
	if abs, err := filepath.Abs(marketplace); err == nil {
		if st, err := os.Stat(abs); err == nil && st.IsDir() {
			marketplace = abs
		}
	}

	failed, installed := false, 0
	for _, c := range agentClients {
		path, err := lookPath(c.command)
		if err != nil {
			fmt.Fprintf(stdout, "skip %s: the %q command is not on PATH\n", c.name, c.command)
			continue
		}
		ok := true
		// An enabled plugin is already set up. Avoid marketplace-add errors
		// and unnecessary cache changes on repeat runs.
		if !dryRun {
			if ready, _ := pluginInstalled(c); ready {
				installed++
				fmt.Fprintf(stdout, "ok   %s: plugin already installed.\n", c.name)
				continue
			}
		}
		for _, step := range c.steps {
			argv := make([]string, len(step))
			for i, a := range step {
				argv[i] = strings.ReplaceAll(a, "%s", marketplace)
			}
			if dryRun {
				fmt.Fprintf(stdout, "would run: %s %s\n", c.command, strings.Join(argv, " "))
				continue
			}
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			out, err := runClient(ctx, path, argv...)
			cancel()
			if err != nil {
				// A previously registered marketplace may reject add. Its
				// presence is not success: still attempt and verify installation.
				if len(step) > 1 && step[1] == "marketplace" && registeredMarketplaceMatches(c, path, marketplace) {
					fmt.Fprintf(stdout, "ok   %s: expected marketplace already registered.\n", c.name)
					continue
				}
				fmt.Fprintf(stderr, "%s: %s %s failed: %v\n%s", c.name, c.command, strings.Join(argv, " "), err, out)
				ok, failed = false, true
				break
			}
		}
		if ok && !dryRun {
			if ready, detail := pluginInstalled(c); ready {
				installed++
				fmt.Fprintf(stdout, "ok   %s: plugin installed and enabled.\n", c.name)
			} else {
				failed = true
				fmt.Fprintf(stderr, "FAIL %s: %s\n", c.name, detail)
			}
		}
	}
	if installed == 0 && !failed && !dryRun {
		fmt.Fprintln(stdout, "No agent CLI was found. Install Claude Code or Codex, then run: secrethandoff setup")
		failed = true
	}
	if failed {
		return 1
	}
	return 0
}

// A failed marketplace add is recoverable only if the client reports the
// requested source already registered under our name. Never silently fall back
// to a different repository that happens to use the same marketplace name.
func registeredMarketplaceMatches(c agentClient, path, source string) bool {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := runClient(ctx, path, "plugin", "marketplace", "list", "--json")
	if err != nil {
		return false
	}
	return marketplaceMatches(out, source)
}

func marketplaceMatches(data []byte, source string) bool {
	type entry struct {
		Name              string `json:"name"`
		Source            string `json:"source"`
		Repo              string `json:"repo"`
		Path              string `json:"path"`
		URL               string `json:"url"`
		MarketplaceSource struct {
			Source string `json:"source"`
		} `json:"marketplaceSource"`
	}
	var entries []entry
	if json.Unmarshal(data, &entries) != nil {
		var wrapper struct {
			Marketplaces []entry `json:"marketplaces"`
		}
		if json.Unmarshal(data, &wrapper) != nil {
			return false
		}
		entries = wrapper.Marketplaces
	}
	for _, e := range entries {
		if e.Name != "secrethandoff" {
			continue
		}
		for _, candidate := range []string{e.Repo, e.Path, e.URL, e.MarketplaceSource.Source} {
			if candidate != "" && candidate == source {
				return true
			}
		}
	}
	return false
}

// pluginInstalled reports whether an agent CLI lists the plugin as installed
// and enabled.
func pluginInstalled(c agentClient) (bool, string) {
	path, err := lookPath(c.command)
	if err != nil {
		return false, fmt.Sprintf("the %q command is not on PATH", c.command)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := runClient(ctx, path, c.list...)
	if err != nil {
		return false, fmt.Sprintf("%s %s failed", c.command, strings.Join(c.list, " "))
	}
	if listsPlugin(out) {
		return true, "plugin installed"
	}
	return false, "plugin not installed; run: secrethandoff setup"
}

// listsPlugin reads both list formats: Claude Code prints an array of
// {id, enabled}; Codex prints {installed: [{pluginId, enabled}]}.
func listsPlugin(out []byte) bool {
	type entry struct {
		ID       string `json:"id"`
		PluginID string `json:"pluginId"`
		Enabled  *bool  `json:"enabled"`
	}
	match := func(entries []entry) bool {
		for _, e := range entries {
			if (e.ID == pluginID || e.PluginID == pluginID) && (e.Enabled == nil || *e.Enabled) {
				return true
			}
		}
		return false
	}
	var list []entry
	if json.Unmarshal(out, &list) == nil {
		return match(list)
	}
	var codex struct {
		Installed []entry `json:"installed"`
	}
	if json.Unmarshal(out, &codex) == nil {
		return match(codex.Installed)
	}
	return false
}

// projectHasRules reports whether dir has the rules block that init writes.
func projectHasRules(dir string) (bool, string) {
	for _, name := range []string{"AGENTS.md", "CLAUDE.md", "GEMINI.md", filepath.Join(".cursor", "rules", "secrethandoff.mdc")} {
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err == nil && strings.Contains(string(b), rulesStart) {
			return true, fmt.Sprintf("%s has the secrets rules", name)
		}
	}
	return false, "this folder has no secrets rules; run: secrethandoff init"
}
