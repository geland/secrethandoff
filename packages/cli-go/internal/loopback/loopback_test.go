package loopback

import (
	"net"
	"testing"
)

func TestListenUsesLoopbackAndAFreePort(t *testing.T) {
	a, err := Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer a.Close()
	b, err := Listen()
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	pa, pb := a.Addr().(*net.TCPAddr), b.Addr().(*net.TCPAddr)
	if !pa.IP.Equal(net.IPv4(127, 0, 0, 1)) || pa.Port == 0 || pa.Port == pb.Port {
		t.Fatalf("addresses %v and %v", pa, pb)
	}
	// A second plain bind of the same port fails on every OS.
	if l, err := net.Listen("tcp", pa.String()); err == nil {
		l.Close()
		t.Fatal("bound a port that a listener holds")
	}
}
