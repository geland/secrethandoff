//go:build windows

package loopback

import "syscall"

// soExclusiveAddrUse is SO_EXCLUSIVEADDRUSE, defined by Winsock as
// ~SO_REUSEADDR.
const soExclusiveAddrUse = ^syscall.SO_REUSEADDR

// control sets SO_EXCLUSIVEADDRUSE before bind. Without it, a program of the
// same user can bind the same address and port with SO_REUSEADDR and receive
// connections meant for this one (threat model T-43, R-05). Go does not set
// it by default.
func control(_, _ string, c syscall.RawConn) error {
	var serr error
	err := c.Control(func(fd uintptr) {
		serr = syscall.SetsockoptInt(syscall.Handle(fd), syscall.SOL_SOCKET, soExclusiveAddrUse, 1)
	})
	if err != nil {
		return err
	}
	return serr
}
