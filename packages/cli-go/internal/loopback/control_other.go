//go:build !windows

package loopback

import "syscall"

// control does nothing: on macOS and Linux a second socket cannot bind an
// address and port that a listening socket holds unless both sockets set
// SO_REUSEPORT, which this one does not.
func control(_, _ string, _ syscall.RawConn) error { return nil }
