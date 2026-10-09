//go:build linux

package hardening

import "syscall"

const prSetDumpable = 4

func apply() []error {
	var errs []error
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0}); err != nil {
		errs = append(errs, err)
	}
	// PR_SET_DUMPABLE 0 also stops ptrace attach by other same-user processes.
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetDumpable, 0, 0); e != 0 {
		errs = append(errs, e)
	}
	return errs
}
