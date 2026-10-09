// Package loopback opens the binary's listeners on 127.0.0.1 with a port
// that the OS picks, so they never collide with another program's port.
package loopback

import (
	"context"
	"net"
)

// Listen binds 127.0.0.1 on a free port. On Windows the socket is exclusive,
// so another program cannot bind the same port while it is open.
func Listen() (net.Listener, error) {
	lc := net.ListenConfig{Control: control}
	return lc.Listen(context.Background(), "tcp", "127.0.0.1:0")
}
