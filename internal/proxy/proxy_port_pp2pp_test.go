package proxy

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

// TestProxyPortToProxyPort_SOCKS5UDP tests SOCKS5 UDP ASSOCIATE through
// two real proxyPortListener instances chained together.
//
// Topology:
//
//	UDP Echo Server (target)
//	     ↑ (direct UDP)
//	Proxy Port B (proxyPortListener, SOCKS5, direct outbound)
//	     ↑ (SOCKS5 UDP ASSOCIATE via outbound node)
//	Proxy Port A (proxyPortListener, SOCKS5, outbound = SOCKS5 node → B)
//	     ↑ (SOCKS5 UDP ASSOCIATE from client)
//	Client
//
// This test uses real proxyPortListener for BOTH layers, not startSOCKS5Server.
func TestProxyPortToProxyPort_SOCKS5UDP(t *testing.T) {
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

	// 2. Proxy Port B (direct, SOCKS5) — simulates the remote VPS
	mgrB := NewOutboundManagerWithSingboxFactory(nil, NewSingboxCoreFactory())
	if err := mgrB.Start(); err != nil {
		t.Fatalf("start mgrB: %v", err)
	}
	defer mgrB.Stop()

	ppCfgB := &config.ProxyPortConfig{
		ID:           "pp-B-direct",
		ListenAddr:   "127.0.0.1:0",
		Type:         config.ProxyPortTypeSocks5,
		Enabled:      true,
		ProxyOutbound: "", // direct
	}
	dialerPoolB := newProxyPortDialerPool(NewChainFactory(NewSingboxCoreFactory(), mgrB))
	listenerB := newProxyPortListener(ppCfgB, mgrB, dialerPoolB)

	lnB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen B: %v", err)
	}
	defer lnB.Close()

	listenerB.listener = lnB
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	listenerB.ctx = ctxB
	listenerB.cancel = cancelB

	go func() {
		for {
			conn, err := lnB.Accept()
			if err != nil {
				return
			}
			go listenerB.handleConn(conn)
		}
	}()

	ppBAddr := lnB.Addr().String()
	ppBHost, ppBPort := splitHostPort(t, ppBAddr)
	t.Logf("Proxy Port B (direct) at %s", ppBAddr)

	// 3. Outbound manager A with SOCKS5 node pointing to Proxy Port B
	mgrA := NewOutboundManagerWithSingboxFactory(nil, NewSingboxCoreFactory())
	nodeB := &config.ProxyOutbound{
		Name:    "node-ppB",
		Type:    config.ProtocolSOCKS5,
		Server:  ppBHost,
		Port:    ppBPort,
		Enabled: true,
	}
	if err := nodeB.Validate(); err != nil {
		t.Fatalf("validate nodeB: %v", err)
	}
	if err := mgrA.AddOutbound(nodeB); err != nil {
		t.Fatalf("add nodeB: %v", err)
	}
	if err := mgrA.Start(); err != nil {
		t.Fatalf("start mgrA: %v", err)
	}
	defer mgrA.Stop()

	// 4. Proxy Port A (SOCKS5, outbound = node-ppB)
	ppCfgA := &config.ProxyPortConfig{
		ID:           "pp-A-via-B",
		ListenAddr:   "127.0.0.1:0",
		Type:         config.ProxyPortTypeSocks5,
		Enabled:      true,
		ProxyOutbound: "node-ppB",
	}
	dialerPoolA := newProxyPortDialerPool(NewChainFactory(NewSingboxCoreFactory(), mgrA))
	listenerA := newProxyPortListener(ppCfgA, mgrA, dialerPoolA)

	lnA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen A: %v", err)
	}
	defer lnA.Close()

	listenerA.listener = lnA
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	listenerA.ctx = ctxA
	listenerA.cancel = cancelA

	go func() {
		for {
			conn, err := lnA.Accept()
			if err != nil {
				return
			}
			go listenerA.handleConn(conn)
		}
	}()

	t.Logf("Proxy Port A (via B) at %s", lnA.Addr().String())

	// 5. Client SOCKS5 UDP ASSOCIATE to Proxy Port A
	conn, err := net.Dial("tcp", lnA.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy port A: %v", err)
	}
	defer conn.Close()

	// Greeting (no auth)
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("send greeting: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read greeting resp: %v", err)
	}
	if resp[0] != 0x05 || resp[1] != 0x00 {
		t.Fatalf("unexpected greeting resp: %v", resp)
	}

	// UDP ASSOCIATE request
	udpReq := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(udpReq); err != nil {
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
	t.Logf("Client relay at %s (proxy port A)", relayAddr)

	// 6. Send UDP datagram through the relay to the echo server
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	defer clientUDP.Close()

	testData := []byte("hello-pp2pp-udp-relay")
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
	t.Logf("UDP echo through pp→pp chain: %d bytes match", len(respData))

	conn.Close()
	time.Sleep(200 * time.Millisecond)
}

// TestProxyPortToProxyPort_SOCKS5UDP_WithAuth tests the same pp→pp chain
// but with username/password auth on both proxy ports.
func TestProxyPortToProxyPort_SOCKS5UDP_WithAuth(t *testing.T) {
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

	// 2. Proxy Port B (direct, SOCKS5, with auth)
	mgrB := NewOutboundManagerWithSingboxFactory(nil, NewSingboxCoreFactory())
	if err := mgrB.Start(); err != nil {
		t.Fatalf("start mgrB: %v", err)
	}
	defer mgrB.Stop()

	ppCfgB := &config.ProxyPortConfig{
		ID:           "pp-B-auth",
		ListenAddr:   "127.0.0.1:0",
		Type:         config.ProxyPortTypeSocks5,
		Enabled:      true,
		ProxyOutbound: "",
		Username:     "userB",
		Password:     "passB",
	}
	dialerPoolB := newProxyPortDialerPool(NewChainFactory(NewSingboxCoreFactory(), mgrB))
	listenerB := newProxyPortListener(ppCfgB, mgrB, dialerPoolB)

	lnB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen B: %v", err)
	}
	defer lnB.Close()

	listenerB.listener = lnB
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	listenerB.ctx = ctxB
	listenerB.cancel = cancelB

	go func() {
		for {
			conn, err := lnB.Accept()
			if err != nil {
				return
			}
			go listenerB.handleConn(conn)
		}
	}()

	ppBAddr := lnB.Addr().String()
	ppBHost, ppBPort := splitHostPort(t, ppBAddr)
	t.Logf("Proxy Port B (auth) at %s", ppBAddr)

	// 3. Outbound manager A with SOCKS5 node pointing to Proxy Port B (with auth)
	mgrA := NewOutboundManagerWithSingboxFactory(nil, NewSingboxCoreFactory())
	nodeB := &config.ProxyOutbound{
		Name:     "node-ppB-auth",
		Type:     config.ProtocolSOCKS5,
		Server:   ppBHost,
		Port:     ppBPort,
		Username: "userB",
		Password: "passB",
		Enabled:  true,
	}
	if err := nodeB.Validate(); err != nil {
		t.Fatalf("validate nodeB: %v", err)
	}
	if err := mgrA.AddOutbound(nodeB); err != nil {
		t.Fatalf("add nodeB: %v", err)
	}
	if err := mgrA.Start(); err != nil {
		t.Fatalf("start mgrA: %v", err)
	}
	defer mgrA.Stop()

	// 4. Proxy Port A (SOCKS5, auth, outbound = node-ppB-auth)
	ppCfgA := &config.ProxyPortConfig{
		ID:           "pp-A-auth-via-B",
		ListenAddr:   "127.0.0.1:0",
		Type:         config.ProxyPortTypeSocks5,
		Enabled:      true,
		ProxyOutbound: "node-ppB-auth",
		Username:     "userA",
		Password:     "passA",
	}
	dialerPoolA := newProxyPortDialerPool(NewChainFactory(NewSingboxCoreFactory(), mgrA))
	listenerA := newProxyPortListener(ppCfgA, mgrA, dialerPoolA)

	lnA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen A: %v", err)
	}
	defer lnA.Close()

	listenerA.listener = lnA
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	listenerA.ctx = ctxA
	listenerA.cancel = cancelA

	go func() {
		for {
			conn, err := lnA.Accept()
			if err != nil {
				return
			}
			go listenerA.handleConn(conn)
		}
	}()

	t.Logf("Proxy Port A (auth, via B) at %s", lnA.Addr().String())

	// 5. Client SOCKS5 UDP ASSOCIATE to Proxy Port A (with auth)
	conn, err := net.Dial("tcp", lnA.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy port A: %v", err)
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
	authReq := []byte{0x01, 0x05, 'u', 's', 'e', 'r', 'A', 0x05, 'p', 'a', 's', 's', 'A'}
	if _, err := conn.Write(authReq); err != nil {
		t.Fatalf("send auth: %v", err)
	}
	authResp := make([]byte, 2)
	if _, err := io.ReadFull(conn, authResp); err != nil {
		t.Fatalf("read auth resp: %v", err)
	}
	if authResp[1] != 0x00 {
		t.Fatalf("auth failed: %v", authResp)
	}

	// UDP ASSOCIATE request
	udpReq := []byte{0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0}
	if _, err := conn.Write(udpReq); err != nil {
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
	t.Logf("Client relay at %s (proxy port A)", relayAddr)

	// 6. Send and receive
	clientUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("listen UDP: %v", err)
	}
	defer clientUDP.Close()

	testData := []byte("auth-pp2pp-udp-works")
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
	if n < 10 {
		t.Fatalf("response too short: %d bytes", n)
	}
	respData := respBuf[10:n]
	if len(respData) != len(testData) {
		t.Fatalf("expected %d bytes, got %d", len(testData), len(respData))
	}
	t.Logf("UDP echo through auth pp→pp chain: %d bytes match", len(respData))

	conn.Close()
	time.Sleep(200 * time.Millisecond)
}

// TestProxyPortToProxyPort_TCP_Connect tests TCP CONNECT through two
// real proxyPortListener instances chained together.
func TestProxyPortToProxyPort_TCP_Connect(t *testing.T) {
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

	// 2. Proxy Port B (direct, SOCKS5)
	mgrB := NewOutboundManagerWithSingboxFactory(nil, NewSingboxCoreFactory())
	if err := mgrB.Start(); err != nil {
		t.Fatalf("start mgrB: %v", err)
	}
	defer mgrB.Stop()

	ppCfgB := &config.ProxyPortConfig{
		ID:           "pp-B-tcp",
		ListenAddr:   "127.0.0.1:0",
		Type:         config.ProxyPortTypeSocks5,
		Enabled:      true,
		ProxyOutbound: "",
	}
	dialerPoolB := newProxyPortDialerPool(NewChainFactory(NewSingboxCoreFactory(), mgrB))
	listenerB := newProxyPortListener(ppCfgB, mgrB, dialerPoolB)

	lnB, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen B: %v", err)
	}
	defer lnB.Close()

	listenerB.listener = lnB
	ctxB, cancelB := context.WithCancel(context.Background())
	defer cancelB()
	listenerB.ctx = ctxB
	listenerB.cancel = cancelB

	go func() {
		for {
			conn, err := lnB.Accept()
			if err != nil {
				return
			}
			go listenerB.handleConn(conn)
		}
	}()

	ppBAddr := lnB.Addr().String()
	ppBHost, ppBPort := splitHostPort(t, ppBAddr)

	// 3. Outbound manager A → node pointing to B
	mgrA := NewOutboundManagerWithSingboxFactory(nil, NewSingboxCoreFactory())
	nodeB := &config.ProxyOutbound{
		Name:    "node-ppB-tcp",
		Type:    config.ProtocolSOCKS5,
		Server:  ppBHost,
		Port:    ppBPort,
		Enabled: true,
	}
	if err := mgrA.AddOutbound(nodeB); err != nil {
		t.Fatalf("add nodeB: %v", err)
	}
	if err := mgrA.Start(); err != nil {
		t.Fatalf("start mgrA: %v", err)
	}
	defer mgrA.Stop()

	// 4. Proxy Port A
	ppCfgA := &config.ProxyPortConfig{
		ID:           "pp-A-tcp-via-B",
		ListenAddr:   "127.0.0.1:0",
		Type:         config.ProxyPortTypeSocks5,
		Enabled:      true,
		ProxyOutbound: "node-ppB-tcp",
	}
	dialerPoolA := newProxyPortDialerPool(NewChainFactory(NewSingboxCoreFactory(), mgrA))
	listenerA := newProxyPortListener(ppCfgA, mgrA, dialerPoolA)

	lnA, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen A: %v", err)
	}
	defer lnA.Close()

	listenerA.listener = lnA
	ctxA, cancelA := context.WithCancel(context.Background())
	defer cancelA()
	listenerA.ctx = ctxA
	listenerA.cancel = cancelA

	go func() {
		for {
			conn, err := lnA.Accept()
			if err != nil {
				return
			}
			go listenerA.handleConn(conn)
		}
	}()

	// 5. Client SOCKS5 CONNECT through A → B → echo
	conn, err := net.Dial("tcp", lnA.Addr().String())
	if err != nil {
		t.Fatalf("dial proxy port A: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("send greeting: %v", err)
	}
	resp := make([]byte, 2)
	if _, err := io.ReadFull(conn, resp); err != nil {
		t.Fatalf("read greeting resp: %v", err)
	}

	echoTarget := echoLn.Addr().String()
	host, portStr, _ := net.SplitHostPort(echoTarget)
	port := 0
	binary.BigEndian.PutUint16([]byte{0, 0}, 0)
	for i := 0; i < len(portStr); i++ {
		port = port*10 + int(portStr[i]-'0')
	}
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

	testData := "hello-pp2pp-tcp"
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
	t.Logf("TCP echo through pp→pp chain: %d bytes match", n)
}
