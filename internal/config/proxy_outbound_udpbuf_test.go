package config

import "testing"

func TestProxyOutboundValidateUDPSocketBufferSize(t *testing.T) {
	for _, tc := range []struct {
		size int
		ok   bool
	}{{0, true}, {-1, true}, {1 << 20, true}, {-2, false}} {
		ob := &ProxyOutbound{Name: "n", Type: ProtocolSOCKS5, Server: "127.0.0.1", Port: 1080, Enabled: true, UDPSocketBufferSize: tc.size}
		if err := ob.Validate(); (err == nil) != tc.ok {
			t.Fatalf("udp_socket_buffer_size=%d: err=%v, want ok=%v", tc.size, err, tc.ok)
		}
	}
	a := &ProxyOutbound{Name: "n", UDPSocketBufferSize: 262144}
	if c := a.Clone(); c.UDPSocketBufferSize != 262144 || !a.Equal(c) {
		t.Fatal("UDPSocketBufferSize not carried by Clone/Equal")
	}
	if b := a.Clone(); func() bool { b.UDPSocketBufferSize = 1; return a.Equal(b) }() {
		t.Fatal("Equal ignores UDPSocketBufferSize")
	}
}
