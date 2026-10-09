//go:build windows

package loopback

import (
	"net"
	"syscall"
	"testing"
)

// TestExclusiveAgainstReuseAddr: a socket that sets SO_REUSEADDR, as a
// hijacking program would, cannot bind the port that Listen holds.
func TestExclusiveAgainstReuseAddr(t *testing.T) {
	l, err := Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	port := l.Addr().(*net.TCPAddr).Port

	s, err := syscall.Socket(syscall.AF_INET, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		t.Fatal(err)
	}
	defer syscall.Closesocket(s)
	if err := syscall.SetsockoptInt(s, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Bind(s, &syscall.SockaddrInet4{Port: port, Addr: [4]byte{127, 0, 0, 1}}); err == nil {
		t.Fatal("a SO_REUSEADDR socket bound the exclusive port")
	}
}
