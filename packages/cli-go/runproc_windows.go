//go:build windows

package main

import "os/exec"

// prepareProcess keeps the default stop, which ends only the command itself.
// cmd.WaitDelay still makes run_with_secret return when a child process
// keeps the output pipes open.
func prepareProcess(cmd *exec.Cmd) {}
