//go:build unix

package main

import (
	"os/exec"
	"syscall"
)

// prepareProcess starts the command in its own process group, so that a
// stop at the time limit also stops the processes that it started, such as
// the session-manager-plugin child of "aws ecs execute-command".
func prepareProcess(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	cmd.Cancel = func() error {
		return syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
	}
}
