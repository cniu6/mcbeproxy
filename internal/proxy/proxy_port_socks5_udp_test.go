package proxy

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

// TestProxyPortSOCKS5UDPAssociate verifies that the proxy port SOCKS5 server
// correctly handles UDP ASSOCIATE requests and relays UDP datagrams.
func TestProxyPortSOCKS5UDPAssociate(t *testing.T) {
	// Start a UDP echo server as the target
	udpEcho, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("start UDP echo: %v", err)
	}
	defer udpEcho.Close()

	echoAddr := udpEcho.LocalAddr().(*net.UDPAddr)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := udpEcho.ReadFromUDP(buf)
			if err != nil {
				return
			}
			udpEcho.WriteToUDP(buf[:n], addr)
		}
	}()

	// Create a proxy port listener with direct connection (no outbound)
	listener := newProxyPortListener(&config.ProxyPortConfig{
		ID:         "test-socks5-udp",
		ListenAddr: "127.0.0.1:0",
		Type:       config.ProxyPortTypeSocks5,
		Enabled:    true,
	}, nil, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	listener.listener = ln
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener.ctx = ctx
	listener.cancel = cancel

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go listener.handleConn(conn)
		}
	}()

	// Connect to the SOCKS5 proxy port
	proxyAddr := ln.Addr().String()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// SOCKS5 greeting (no auth)
	greeting := []byte{0x05, 0x01, 0x00}
	if _, err := conn.Write(greeting); err != nil {
		t.Fatalf("send greeting: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read greeting resp: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("unexpected greeting resp: %v", resp)
	}

	// Send UDP ASSOCIATE request
	// DST.ADDR = 0.0.0.0:0 (client doesn't know its source addr yet)
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("send UDP ASSOCIATE: %v", err)
	}

	// Read reply
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read UDP ASSOCIATE reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("UDP ASSOCIATE failed with reply code %d", reply[1])
	}

	// Parse relay address
	relayIP := net.IP(reply[4:8])
	relayPort := int(binary.BigEndian.Uint16(reply[8:10]))
	if relayIP.IsUnspecified() {
		relayIP = net.IPv4(127, 0, 0, 1)
	}
	relayAddr := &net.UDPAddr{IP: relayIP, Port: relayPort}
	t.Logf("UDP relay at %s", relayAddr)

	// Create local UDP socket to talk to the relay
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	defer clientUDP.Close()

	// Send a datagram to the echo server through the relay
	// SOCKS5 UDP header: RSV(2) + FRAG(1) + ATYP(1) + ADDR + PORT + DATA
	testData := []byte("hello-udp-associate")
	udpHeader := []byte{0x00, 0x00, 0x00, 0x01} // RSV + FRAG + ATYP=IPv4
	udpHeader = append(udpHeader, echoAddr.IP.To4()...)
	udpHeader = append(udpHeader, byte(echoAddr.Port>>8), byte(echoAddr.Port&0xFF))
	datagram := append(udpHeader, testData...)

	_ = clientUDP.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := clientUDP.WriteToUDP(datagram, relayAddr); err != nil {
		t.Fatalf("write to relay: %v", err)
	}

	// Read response from relay
	_ = clientUDP.SetReadDeadline(time.Now().Add(10 * time.Second))
	respBuf := make([]byte, 65535)
	n, _, err := clientUDP.ReadFromUDP(respBuf)
	if err != nil {
		t.Fatalf("read from relay: %v", err)
	}
	if n < 10 {
		t.Fatalf("response too short: %d bytes", n)
	}

	// Parse SOCKS5 UDP response header
	respData := respBuf[10:n]
	if len(respData) != len(testData) {
		t.Fatalf("expected %d bytes, got %d", len(testData), len(respData))
	}
	for i := 0; i < len(testData); i++ {
		if respData[i] != testData[i] {
			t.Fatalf("byte mismatch at %d: expected %c, got %c", i, testData[i], respData[i])
		}
	}
	t.Logf("UDP echo through SOCKS5 UDP ASSOCIATE: %d bytes match", len(respData))

	// Close control connection
	conn.Close()
	time.Sleep(100 * time.Millisecond)
}

// TestProxyPortSOCKS5UDPAssociateWithAuth tests UDP ASSOCIATE with username/password auth.
func TestProxyPortSOCKS5UDPAssociateWithAuth(t *testing.T) {
	// Start a UDP echo server
	udpEcho, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("start UDP echo: %v", err)
	}
	defer udpEcho.Close()

	echoAddr := udpEcho.LocalAddr().(*net.UDPAddr)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := udpEcho.ReadFromUDP(buf)
			if err != nil {
				return
			}
			udpEcho.WriteToUDP(buf[:n], addr)
		}
	}()

	listener := newProxyPortListener(&config.ProxyPortConfig{
		ID:         "test-socks5-udp-auth",
		ListenAddr: "127.0.0.1:0",
		Type:       config.ProxyPortTypeSocks5,
		Enabled:    true,
		Username:   "user",
		Password:   "pass",
	}, nil, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	listener.listener = ln
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener.ctx = ctx
	listener.cancel = cancel

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go listener.handleConn(conn)
		}
	}()

	proxyAddr := ln.Addr().String()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy: %v", err)
	}
	defer conn.Close()

	// SOCKS5 greeting with user/pass auth
	greeting := []byte{0x05, 0x02, 0x00, 0x02}
	if _, err := conn.Write(greeting); err != nil {
		t.Fatalf("send greeting: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read greeting resp: %v", err)
	}
	if resp[1] != 0x02 {
		t.Fatalf("expected user/pass auth (0x02), got %d", resp[1])
	}

	// Send auth
	auth := []byte{0x01, 0x04, 'u', 's', 'e', 'r', 0x04, 'p', 'a', 's', 's'}
	if _, err := conn.Write(auth); err != nil {
		t.Fatalf("send auth: %v", err)
	}
	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil {
		t.Fatalf("read auth resp: %v", err)
	}
	if authResp[1] != 0x00 {
		t.Fatalf("auth failed: %v", authResp)
	}

	// Send UDP ASSOCIATE
	req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(req); err != nil {
		t.Fatalf("send UDP ASSOCIATE: %v", err)
	}
	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read UDP ASSOCIATE reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("UDP ASSOCIATE failed with reply code %d", reply[1])
	}

	relayIP := net.IP(reply[4:8])
	relayPort := int(binary.BigEndian.Uint16(reply[8:10]))
	if relayIP.IsUnspecified() {
		relayIP = net.IPv4(127, 0, 0, 1)
	}
	relayAddr := &net.UDPAddr{IP: relayIP, Port: relayPort}

	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	defer clientUDP.Close()

	testData := []byte("auth-udp-works")
	udpHeader := []byte{0x00, 0x00, 0x00, 0x01}
	udpHeader = append(udpHeader, echoAddr.IP.To4()...)
	udpHeader = append(udpHeader, byte(echoAddr.Port>>8), byte(echoAddr.Port&0xFF))
	datagram := append(udpHeader, testData...)

	_ = clientUDP.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err := clientUDP.WriteToUDP(datagram, relayAddr); err != nil {
		t.Fatalf("write to relay: %v", err)
	}

	_ = clientUDP.SetReadDeadline(time.Now().Add(10 * time.Second))
	respBuf := make([]byte, 65535)
	n, _, err := clientUDP.ReadFromUDP(respBuf)
	if err != nil {
		t.Fatalf("read from relay: %v", err)
	}
	respData := respBuf[10:n]
	if len(respData) != len(testData) {
		t.Fatalf("expected %d bytes, got %d", len(testData), len(respData))
	}
	t.Logf("UDP echo through SOCKS5 UDP ASSOCIATE with auth: %d bytes match", len(respData))

	conn.Close()
	time.Sleep(100 * time.Millisecond)
}

// Ensure fmt is used
var _ = fmt.Sprintf

// TestProxyPortSOCKS5UDPRapidReconnect verifies that rapidly disconnecting
// and reconnecting a SOCKS5 UDP ASSOCIATE from the same IP does not kill the
// new connection's upstream. This is a regression test for a race condition
// in unregisterClientIP where the old connection's cleanup would close the
// new connection's upstreams.
func TestProxyPortSOCKS5UDPRapidReconnect(t *testing.T) {
	// Start a UDP echo server as the target
	udpEcho, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("start UDP echo: %v", err)
	}
	defer udpEcho.Close()

	echoAddr := udpEcho.LocalAddr().(*net.UDPAddr)
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := udpEcho.ReadFromUDP(buf)
			if err != nil {
				return
			}
			udpEcho.WriteToUDP(buf[:n], addr)
		}
	}()

	listener := newProxyPortListener(&config.ProxyPortConfig{
		ID:         "test-rapid-reconnect",
		ListenAddr: "127.0.0.1:0",
		Type:       config.ProxyPortTypeSocks5,
		Enabled:    true,
	}, nil, nil)

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()

	listener.listener = ln
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	listener.ctx = ctx
	listener.cancel = cancel

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go listener.handleConn(conn)
		}
	}()

	proxyAddr := ln.Addr().String()
	echoIP := echoAddr.IP.To4()
	echoPort := echoAddr.Port

	// Perform 6 cycles of connect → ping → disconnect
	// With reuseCount=3 on the client side, this simulates rapid reconnection
	// after cache eviction. The server must not close the new upstream when
	// the old TCP control connection's cleanup runs.
	for cycle := 0; cycle < 6; cycle++ {
		conn, err := net.Dial("tcp", proxyAddr)
		if err != nil {
			t.Fatalf("cycle %d: dial proxy: %v", cycle, err)
		}

		// SOCKS5 greeting
		greeting := []byte{0x05, 0x01, 0x00}
		if _, err := conn.Write(greeting); err != nil {
			t.Fatalf("cycle %d: send greeting: %v", cycle, err)
		}
		resp := make([]byte, 2)
		if _, err := io.ReadFull(conn, resp); err != nil {
			t.Fatalf("cycle %d: read greeting resp: %v", cycle, err)
		}

		// UDP ASSOCIATE
		req := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
		if _, err := conn.Write(req); err != nil {
			t.Fatalf("cycle %d: send UDP ASSOCIATE: %v", cycle, err)
		}
		reply := make([]byte, 10)
		if _, err := io.ReadFull(conn, reply); err != nil {
			t.Fatalf("cycle %d: read UDP ASSOCIATE reply: %v", cycle, err)
		}
		if reply[1] != 0x00 {
			t.Fatalf("cycle %d: UDP ASSOCIATE failed with reply code %d", cycle, reply[1])
		}

		relayIP := net.IP(reply[4:8])
		relayPort := int(binary.BigEndian.Uint16(reply[8:10]))
		if relayIP.IsUnspecified() {
			relayIP = net.IPv4(127, 0, 0, 1)
		}
		relayAddr := &net.UDPAddr{IP: relayIP, Port: relayPort}

		clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			t.Fatalf("cycle %d: listen UDP: %v", cycle, err)
		}

		testData := []byte("rapid-reconnect-test")
		udpHeader := []byte{0x00, 0x00, 0x00, 0x01}
		udpHeader = append(udpHeader, echoIP...)
		udpHeader = append(udpHeader, byte(echoPort>>8), byte(echoPort&0xFF))
		datagram := append(udpHeader, testData...)

		_ = clientUDP.SetWriteDeadline(time.Now().Add(5 * time.Second))
		if _, err := clientUDP.WriteToUDP(datagram, relayAddr); err != nil {
			t.Fatalf("cycle %d: write to relay: %v", cycle, err)
		}

		_ = clientUDP.SetReadDeadline(time.Now().Add(5 * time.Second))
		respBuf := make([]byte, 65535)
		n, _, err := clientUDP.ReadFromUDP(respBuf)
		if err != nil {
			t.Fatalf("cycle %d: read from relay: %v (upstream may have been killed by old cleanup)", cycle, err)
		}
		if n < 10 {
			t.Fatalf("cycle %d: response too short: %d bytes", cycle, n)
		}
		respData := respBuf[10:n]
		if len(respData) != len(testData) {
			t.Fatalf("cycle %d: expected %d bytes, got %d", cycle, len(testData), len(respData))
		}

		clientUDP.Close()
		conn.Close()
		t.Logf("Cycle %d: ok", cycle)
	}
}
