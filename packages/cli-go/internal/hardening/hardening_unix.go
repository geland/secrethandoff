//go:build darwin || freebsd || netbsd || openbsd

package hardening

import "syscall"

func apply() []error {
	if err := syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{Cur: 0, Max: 0}); err != nil {
		return []error{err}
	}
	return nil
}
