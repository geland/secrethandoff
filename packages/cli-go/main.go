// Command secrethandoff gives secrets to AI agents without the value entering
// the chat or the model context. See docs/adr/0009-local-secret-requests-for-agents.md.
package main

import (
	"fmt"
	"io"
	"os"
)

const version = "0.0.1"

const usage = `secrethandoff gives secrets to AI agents without the value entering the chat.

Usage:
  secrethandoff mcp            Run the stdio MCP server. Agent clients start this command.
  secrethandoff doctor [--json]  Check that local mode can work on this computer.
  secrethandoff setup [--init | --no-init] [--bin-dir DIR] [--marketplace SOURCE] [--dry-run]
                               Install this binary, connect agents, and verify setup.
  secrethandoff init           Add the secrets rules to this project's agent rule files.
  secrethandoff hook user-prompt|bash  Claude Code hook: stop a pasted or literal secret.
  secrethandoff fill <link>    Fill a request link from this terminal instead of a browser.
  secrethandoff version        Print the version.
  secrethandoff help           Print this help.
`

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run returns the process exit code. It never writes a secret or a token to
// stdout or stderr (AGENTS.md, local binary invariants).
func run(args []string, stdout, stderr io.Writer) int {
	return runWithInput(args, os.Stdin, stdout, stderr)
}

func runWithInput(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "mcp":
		if err := runMCP(); err != nil {
			fmt.Fprintln(stderr, "secrethandoff mcp:", err)
			return 1
		}
		return 0
	case "doctor":
		return runDoctor(args[1:], stdout)
	case "setup":
		return runSetupWithInput(args[1:], stdin, stdout, stderr)
	case "fill":
		return runFill(args[1:], stdin, stdout, stderr)
	case "hook":
		return runHook(args[1:], stdin, stdout, stderr)
	case "init":
		dir, err := os.Getwd()
		if err == nil {
			err = runInit(dir, stdout)
		}
		if err != nil {
			fmt.Fprintln(stderr, "secrethandoff init:", err)
			return 1
		}
		return 0
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, version)
		return 0
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}
