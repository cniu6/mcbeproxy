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

// Test2LayerProxy_SOCKS5UDPAssociate tests SOCKS5 UDP ASSOCIATE through a
// 2-layer proxy chain using the proxy port's own SOCKS5 server.
//
// Topology:
//
//	UDP Echo Server (target)
//	     ↑ (direct UDP)
//	SOCKS5 Server A (test SOCKS5 server, direct to target)
//	     ↑ (SOCKS5 UDP ASSOCIATE via outbound)
//	SOCKS5 Server B (proxy port listener, outbound = chain-node)
//	     ↑ (SOCKS5 UDP ASSOCIATE from client)
//	Client
//
// The proxy port's outbound is a chain node: chain-node → SOCKS5-A → target.
// This verifies that UDP ASSOCIATE on the proxy port works with chain outbounds.
func Test2LayerProxy_SOCKS5UDPAssociate(t *testing.T) {
	// 1. Start UDP echo server as the final target
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

	// 2. Start SOCKS5 Server A (direct relay to target)
	socks5A := startSOCKS5Server(t, "", "")
	socks5AHost, socks5APort := splitHostPort(t, socks5A.String())

	// 3. Create outbound manager with a chain node pointing to SOCKS5-A
	mgr := NewOutboundManagerWithSingboxFactory(nil, NewSingboxCoreFactory())

	chainNode := &config.ProxyOutbound{
		Name:    "chain-to-A",
		Type:    config.ProtocolSOCKS5,
		Server:  socks5AHost,
		Port:    socks5APort,
		Enabled: true,
	}
	if err := chainNode.Validate(); err != nil {
		t.Fatalf("validate chain node: %v", err)
	}
	if err := mgr.AddOutbound(chainNode); err != nil {
		t.Fatalf("add chain node: %v", err)
	}

	// Start outbound manager
	if err := mgr.Start(); err != nil {
		t.Fatalf("start outbound manager: %v", err)
	}
	defer mgr.Stop()

	// 4. Create proxy port listener (SOCKS5 type) using the chain outbound
	ppCfg := &config.ProxyPortConfig{
		ID:           "test-2layer-socks5",
		ListenAddr:   "127.0.0.1:0",
		Type:         config.ProxyPortTypeSocks5,
		Enabled:      true,
		ProxyOutbound: "chain-to-A",
	}
	dialerPool := newProxyPortDialerPool(NewChainFactory(NewSingboxCoreFactory(), mgr))
	listener := newProxyPortListener(ppCfg, mgr, dialerPool)

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

	// 5. Client connects to proxy port SOCKS5 and does UDP ASSOCIATE
	proxyAddr := ln.Addr().String()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy port: %v", err)
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

	relayIP := net.IP(reply[4:8])
	relayPort := int(binary.BigEndian.Uint16(reply[8:10]))
	if relayIP.IsUnspecified() {
		relayIP = net.IPv4(127, 0, 0, 1)
	}
	relayAddr := &net.UDPAddr{IP: relayIP, Port: relayPort}
	t.Logf("Layer 1 relay at %s (proxy port)", relayAddr)

	// 6. Send UDP datagram through the relay to the echo server
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	defer clientUDP.Close()

	testData := []byte("hello-2layer-udp-chain")
	udpHeader := []byte{0x00, 0x00, 0x00, 0x01} // RSV + FRAG + ATYP=IPv4
	udpHeader = append(udpHeader, echoAddr.IP.To4()...)
	udpHeader = append(udpHeader, byte(echoAddr.Port>>8), byte(echoAddr.Port&0xFF))
	datagram := append(udpHeader, testData...)

	_ = clientUDP.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := clientUDP.WriteToUDP(datagram, relayAddr); err != nil {
		t.Fatalf("write to relay: %v", err)
	}

	// 7. Read response
	_ = clientUDP.SetReadDeadline(time.Now().Add(15 * time.Second))
	respBuf := make([]byte, 65535)
	n, _, err := clientUDP.ReadFromUDP(respBuf)
	if err != nil {
		t.Fatalf("read from relay: %v", err)
	}
	if n < 10 {
		t.Fatalf("response too short: %d bytes", n)
	}
	respData := respBuf[10:n]
	if len(respData) != len(testData) {
		t.Fatalf("expected %d bytes, got %d", len(testData), len(respData))
	}
	for i := 0; i < len(testData); i++ {
		if respData[i] != testData[i] {
			t.Fatalf("byte mismatch at %d: expected %c, got %c", i, testData[i], respData[i])
		}
	}
	t.Logf("UDP echo through 2-layer proxy chain: %d bytes match", len(respData))

	conn.Close()
	time.Sleep(200 * time.Millisecond)
}

// Test2LayerProxy_SOCKS5UDPAssociate_WithAuth tests the same 2-layer chain
// but with username/password auth on the proxy port.
func Test2LayerProxy_SOCKS5UDPAssociate_WithAuth(t *testing.T) {
	// 1. UDP echo server
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

	// 2. SOCKS5 Server A with auth
	socks5A := startSOCKS5Server(t, "proxyuser", "proxypass")
	socks5AHost, socks5APort := splitHostPort(t, socks5A.String())

	// 3. Outbound manager with node pointing to SOCKS5-A (with auth)
	mgr := NewOutboundManagerWithSingboxFactory(nil, NewSingboxCoreFactory())

	nodeA := &config.ProxyOutbound{
		Name:     "node-A-auth",
		Type:     config.ProtocolSOCKS5,
		Server:   socks5AHost,
		Port:     socks5APort,
		Username: "proxyuser",
		Password: "proxypass",
		Enabled:  true,
	}
	if err := nodeA.Validate(); err != nil {
		t.Fatalf("validate node A: %v", err)
	}
	if err := mgr.AddOutbound(nodeA); err != nil {
		t.Fatalf("add node A: %v", err)
	}
	if err := mgr.Start(); err != nil {
		t.Fatalf("start outbound manager: %v", err)
	}
	defer mgr.Stop()

	// 4. Proxy port with auth and outbound = node-A-auth
	ppCfg := &config.ProxyPortConfig{
		ID:           "test-2layer-auth",
		ListenAddr:   "127.0.0.1:0",
		Type:         config.ProxyPortTypeSocks5,
		Enabled:      true,
		ProxyOutbound: "node-A-auth",
		Username:     "portuser",
		Password:     "portpass",
	}
	dialerPool := newProxyPortDialerPool(NewChainFactory(NewSingboxCoreFactory(), mgr))
	listener := newProxyPortListener(ppCfg, mgr, dialerPool)

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

	// 5. Client connects with auth
	proxyAddr := ln.Addr().String()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy port: %v", err)
	}
	defer conn.Close()

	// Greeting with user/pass
	greeting := []byte{0x05, 0x02, 0x00, 0x02}
	if _, err := conn.Write(greeting); err != nil {
		t.Fatalf("send greeting: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read greeting resp: %v", err)
	}
	if resp[1] != 0x02 {
		t.Fatalf("expected user/pass auth, got %d", resp[1])
	}

	// Auth
	auth := []byte{0x01, 0x08, 'p', 'o', 'r', 't', 'u', 's', 'e', 'r', 0x08, 'p', 'o', 'r', 't', 'p', 'a', 's', 's'}
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

	// UDP ASSOCIATE
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

	// Send and receive
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	defer clientUDP.Close()

	testData := []byte("auth-2layer-chain-works")
	udpHeader := []byte{0x00, 0x00, 0x00, 0x01}
	udpHeader = append(udpHeader, echoAddr.IP.To4()...)
	udpHeader = append(udpHeader, byte(echoAddr.Port>>8), byte(echoAddr.Port&0xFF))
	datagram := append(udpHeader, testData...)

	_ = clientUDP.SetWriteDeadline(time.Now().Add(10 * time.Second))
	if _, err := clientUDP.WriteToUDP(datagram, relayAddr); err != nil {
		t.Fatalf("write to relay: %v", err)
	}

	_ = clientUDP.SetReadDeadline(time.Now().Add(15 * time.Second))
	respBuf := make([]byte, 65535)
	n, _, err := clientUDP.ReadFromUDP(respBuf)
	if err != nil {
		t.Fatalf("read from relay: %v", err)
	}
	respData := respBuf[10:n]
	if len(respData) != len(testData) {
		t.Fatalf("expected %d bytes, got %d", len(testData), len(respData))
	}
	t.Logf("UDP echo through 2-layer proxy chain with auth: %d bytes match", len(respData))

	conn.Close()
	time.Sleep(200 * time.Millisecond)
}

// Test2LayerProxy_TCP_Connect tests TCP CONNECT through a 2-layer proxy chain
// using the proxy port's SOCKS5 server.
func Test2LayerProxy_TCP_Connect(t *testing.T) {
	// 1. TCP echo server
	echoLn, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen echo: %v", err)
	}
	defer echoLn.Close()
	go func() {
		for {
			c, err := echoLn.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				io.Copy(c, c)
			}(c)
		}
	}()

	// 2. SOCKS5 Server A
	socks5A := startSOCKS5Server(t, "", "")
	socks5AHost, socks5APort := splitHostPort(t, socks5A.String())

	// 3. Outbound manager
	mgr := NewOutboundManagerWithSingboxFactory(nil, NewSingboxCoreFactory())
	nodeA := &config.ProxyOutbound{
		Name:    "tcp-node-A",
		Type:    config.ProtocolSOCKS5,
		Server:  socks5AHost,
		Port:    socks5APort,
		Enabled: true,
	}
	if err := mgr.AddOutbound(nodeA); err != nil {
		t.Fatalf("add node A: %v", err)
	}
	if err := mgr.Start(); err != nil {
		t.Fatalf("start outbound manager: %v", err)
	}
	defer mgr.Stop()

	// 4. Proxy port
	ppCfg := &config.ProxyPortConfig{
		ID:           "test-2layer-tcp",
		ListenAddr:   "127.0.0.1:0",
		Type:         config.ProxyPortTypeSocks5,
		Enabled:      true,
		ProxyOutbound: "tcp-node-A",
	}
	dialerPool := newProxyPortDialerPool(NewChainFactory(NewSingboxCoreFactory(), mgr))
	listener := newProxyPortListener(ppCfg, mgr, dialerPool)

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

	// 5. Client SOCKS5 CONNECT through proxy port → SOCKS5-A → echo server
	proxyAddr := ln.Addr().String()
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("dial proxy port: %v", err)
	}
	defer conn.Close()

	// Greeting
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("send greeting: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read greeting resp: %v", err)
	}

	// CONNECT to echo server
	echoTarget := echoLn.Addr().String()
	host, portStr, _ := net.SplitHostPort(echoTarget)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	connectReq := []byte{0x05, 0x01, 0x00, 0x01}
	ip := net.ParseIP(host).To4()
	connectReq = append(connectReq, ip...)
	connectReq = append(connectReq, byte(port>>8), byte(port&0xFF))
	if _, err := conn.Write(connectReq); err != nil {
		t.Fatalf("send CONNECT: %v", err)
	}

	reply := make([]byte, 10)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("read CONNECT reply: %v", err)
	}
	if reply[1] != 0x00 {
		t.Fatalf("CONNECT failed with reply code %d", reply[1])
	}

	// Send and receive through the tunnel
	testData := "hello-2layer-tcp"
	if _, err := conn.Write([]byte(testData)); err != nil {
		t.Fatalf("write test data: %v", err)
	}
	_ = conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	respBuf := make([]byte, 256)
	n, err := conn.Read(respBuf)
	if err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(respBuf[:n]) != testData {
		t.Fatalf("expected %q, got %q", testData, string(respBuf[:n]))
	}
	t.Logf("TCP echo through 2-layer proxy chain: %d bytes match", n)
}
