package proxy

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"io"
	"net"
	"strconv"
	"strings"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

// startTCPEcho starts a TCP echo server and returns its address.
func startTCPEcho(t *testing.T) net.Addr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func(conn net.Conn) {
				defer conn.Close()
				io.Copy(conn, conn)
			}(c)
		}
	}()
	return ln.Addr()
}

// startUDPEcho starts a UDP echo server and returns its address.
func startUDPEcho(t *testing.T) *net.UDPAddr {
	t.Helper()
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := conn.ReadFromUDP(buf)
			if err != nil {
				return
			}
			conn.WriteToUDP(buf[:n], addr)
		}
	}()
	return conn.LocalAddr().(*net.UDPAddr)
}

// startSOCKS5Server starts an in-process SOCKS5 server supporting CONNECT and
// UDP ASSOCIATE. If username is non-empty, username/password auth is required.
func startSOCKS5Server(t *testing.T, username, password string) net.Addr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleSOCKS5Conn(t, c, username, password)
		}
	}()
	return ln.Addr()
}

func handleSOCKS5Conn(t *testing.T, c net.Conn, username, password string) {
	defer c.Close()

	// Greeting
	header := make([]byte, 2)
	if _, err := io.ReadFull(c, header); err != nil {
		return
	}
	nMethods := int(header[1])
	methods := make([]byte, nMethods)
	if _, err := io.ReadFull(c, methods); err != nil {
		return
	}

	if username != "" {
		c.Write([]byte{socks5Version, socks5AuthUserPass})
		// user/pass sub-negotiation
		ver := make([]byte, 2)
		if _, err := io.ReadFull(c, ver); err != nil {
			return
		}
		ulen := int(ver[1])
		uname := make([]byte, ulen)
		io.ReadFull(c, uname)
		plenB := make([]byte, 1)
		io.ReadFull(c, plenB)
		passwd := make([]byte, int(plenB[0]))
		io.ReadFull(c, passwd)
		if string(uname) != username || string(passwd) != password {
			c.Write([]byte{socks5UserAuthVer, 0x01})
			return
		}
		c.Write([]byte{socks5UserAuthVer, socks5UserAuthOKVal})
	} else {
		c.Write([]byte{socks5Version, socks5AuthNone})
	}

	// Request
	reqHeader := make([]byte, 3)
	if _, err := io.ReadFull(c, reqHeader); err != nil {
		return
	}
	dest, err := readSocksaddr(c)
	if err != nil {
		return
	}

	switch reqHeader[1] {
	case socks5CmdConnect:
		upstream, err := net.Dial("tcp", dest.String())
		if err != nil {
			c.Write([]byte{socks5Version, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		defer upstream.Close()
		c.Write([]byte{socks5Version, socks5ReplySucceed, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		go io.Copy(upstream, c)
		io.Copy(c, upstream)
	case socks5CmdUDPAssoc:
		relay, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			c.Write([]byte{socks5Version, 0x01, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
			return
		}
		defer relay.Close()
		relayAddr := relay.LocalAddr().(*net.UDPAddr)
		reply := []byte{socks5Version, socks5ReplySucceed, 0x00, 0x01}
		reply = append(reply, relayAddr.IP.To4()...)
		reply = append(reply, byte(relayAddr.Port>>8), byte(relayAddr.Port))
		c.Write(reply)
		go socks5UDPRelayEcho(relay)
		// Hold the association open until the control connection closes.
		io.Copy(io.Discard, c)
	default:
		c.Write([]byte{socks5Version, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	}
}

// socks5UDPRelayEcho relays encapsulated UDP datagrams to the real destination
// and returns the (echoed) response back to the client, re-encapsulated.
func socks5UDPRelayEcho(relay *net.UDPConn) {
	buf := make([]byte, 65535)
	for {
		n, clientAddr, err := relay.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if n < 3 {
			continue
		}
		body := buf[3:n]
		r := bytes.NewReader(body)
		dest, err := readSocksaddr(r)
		if err != nil {
			continue
		}
		consumed := len(body) - r.Len()
		data := body[consumed:]

		up, err := net.Dial("udp", dest.String())
		if err != nil {
			continue
		}
		up.Write(data)
		resp := make([]byte, 65535)
		up.SetReadDeadline(time.Now().Add(2 * time.Second))
		m, err := up.Read(resp)
		up.Close()
		if err != nil {
			continue
		}
		out := []byte{0x00, 0x00, 0x00}
		out = appendSocksaddr(out, dest)
		out = append(out, resp[:m]...)
		relay.WriteToUDP(out, clientAddr)
	}
}

// startHTTPConnectProxy starts an in-process HTTP CONNECT proxy.
func startHTTPConnectProxy(t *testing.T, username, password string) net.Addr {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go handleHTTPConnect(c, username, password)
		}
	}()
	return ln.Addr()
}

func handleHTTPConnect(c net.Conn, username, password string) {
	defer c.Close()
	br := bufio.NewReader(c)
	requestLine, err := br.ReadString('\n')
	if err != nil {
		return
	}
	parts := strings.Fields(requestLine)
	if len(parts) < 2 || parts[0] != "CONNECT" {
		c.Write([]byte("HTTP/1.1 405 Method Not Allowed\r\n\r\n"))
		return
	}
	target := parts[1]

	authOK := username == ""
	for {
		line, err := br.ReadString('\n')
		if err != nil {
			return
		}
		trimmed := strings.TrimRight(line, "\r\n")
		if trimmed == "" {
			break
		}
		if username != "" {
			lower := strings.ToLower(trimmed)
			if strings.HasPrefix(lower, "proxy-authorization:") {
				want := "Basic " + basicAuth(username, password)
				if strings.TrimSpace(trimmed[len("proxy-authorization:"):]) == want {
					authOK = true
				}
			}
		}
	}
	if !authOK {
		c.Write([]byte("HTTP/1.1 407 Proxy Authentication Required\r\n\r\n"))
		return
	}

	upstream, err := net.Dial("tcp", target)
	if err != nil {
		c.Write([]byte("HTTP/1.1 502 Bad Gateway\r\n\r\n"))
		return
	}
	defer upstream.Close()
	c.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
	go io.Copy(upstream, br)
	io.Copy(c, upstream)
}

func basicAuth(username, password string) string {
	return base64.StdEncoding.EncodeToString([]byte(username + ":" + password))
}

func splitHostPortConfig(t *testing.T, addr net.Addr) (string, int) {
	t.Helper()
	host, portStr, err := net.SplitHostPort(addr.String())
	if err != nil {
		t.Fatalf("split host port: %v", err)
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		t.Fatalf("atoi port: %v", err)
	}
	return host, port
}

func TestSOCKS5DialTCP(t *testing.T) {
	echo := startTCPEcho(t)
	proxy := startSOCKS5Server(t, "", "")
	host, port := splitHostPortConfig(t, proxy)

	cfg := &config.ProxyOutbound{Name: "s", Type: config.ProtocolSOCKS5, Server: host, Port: port}
	dialer, err := CreateSingboxDialer(cfg)
	if err != nil {
		t.Fatalf("create dialer: %v", err)
	}
	defer dialer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", echo.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	want := []byte("hello-socks5-tcp")
	if _, err := conn.Write(want); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, len(want))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("echo mismatch: got %q want %q", got, want)
	}
}

func TestSOCKS5DialTCPWithAuth(t *testing.T) {
	echo := startTCPEcho(t)
	proxy := startSOCKS5Server(t, "user", "pass")
	host, port := splitHostPortConfig(t, proxy)

	cfg := &config.ProxyOutbound{Name: "s", Type: config.ProtocolSOCKS5, Server: host, Port: port, Username: "user", Password: "pass"}
	dialer, err := CreateSingboxDialer(cfg)
	if err != nil {
		t.Fatalf("create dialer: %v", err)
	}
	defer dialer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", echo.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	want := []byte("auth-ok")
	conn.Write(want)
	got := make([]byte, len(want))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("echo mismatch: got %q want %q", got, want)
	}
}

func TestSOCKS5DialTCPWrongAuth(t *testing.T) {
	startTCPEcho(t)
	proxy := startSOCKS5Server(t, "user", "pass")
	host, port := splitHostPortConfig(t, proxy)

	cfg := &config.ProxyOutbound{Name: "s", Type: config.ProtocolSOCKS5, Server: host, Port: port, Username: "user", Password: "wrong"}
	dialer, _ := CreateSingboxDialer(cfg)
	defer dialer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if _, err := dialer.DialContext(ctx, "tcp", "127.0.0.1:1"); err == nil {
		t.Fatal("expected auth failure, got nil")
	}
}

func TestSOCKS5UDP(t *testing.T) {
	udpEcho := startUDPEcho(t)
	proxy := startSOCKS5Server(t, "", "")
	host, port := splitHostPortConfig(t, proxy)

	cfg := &config.ProxyOutbound{Name: "s", Type: config.ProtocolSOCKS5, Server: host, Port: port}
	outbound, err := CreateSingboxOutbound(cfg)
	if err != nil {
		t.Fatalf("create outbound: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	pc, err := outbound.ListenPacket(ctx, udpEcho.String())
	if err != nil {
		t.Fatalf("listen packet: %v", err)
	}
	defer pc.Close()

	want := []byte("hello-socks5-udp")
	if _, err := pc.WriteTo(want, udpEcho); err != nil {
		t.Fatalf("write to: %v", err)
	}
	got := make([]byte, 1500)
	pc.SetReadDeadline(time.Now().Add(3 * time.Second))
	n, _, err := pc.ReadFrom(got)
	if err != nil {
		t.Fatalf("read from: %v", err)
	}
	if !bytes.Equal(got[:n], want) {
		t.Fatalf("udp echo mismatch: got %q want %q", got[:n], want)
	}
}

func TestHTTPConnectTCP(t *testing.T) {
	echo := startTCPEcho(t)
	proxy := startHTTPConnectProxy(t, "", "")
	host, port := splitHostPortConfig(t, proxy)

	cfg := &config.ProxyOutbound{Name: "h", Type: config.ProtocolHTTP, Server: host, Port: port}
	dialer, err := CreateSingboxDialer(cfg)
	if err != nil {
		t.Fatalf("create dialer: %v", err)
	}
	defer dialer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", echo.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	want := []byte("hello-http-connect")
	conn.Write(want)
	got := make([]byte, len(want))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("echo mismatch: got %q want %q", got, want)
	}
}

func TestHTTPConnectTCPWithAuth(t *testing.T) {
	echo := startTCPEcho(t)
	proxy := startHTTPConnectProxy(t, "user", "secret")
	host, port := splitHostPortConfig(t, proxy)

	cfg := &config.ProxyOutbound{Name: "h", Type: config.ProtocolHTTP, Server: host, Port: port, Username: "user", Password: "secret"}
	dialer, _ := CreateSingboxDialer(cfg)
	defer dialer.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	conn, err := dialer.DialContext(ctx, "tcp", echo.String())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer conn.Close()

	want := []byte("http-auth-ok")
	conn.Write(want)
	got := make([]byte, len(want))
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("echo mismatch: got %q want %q", got, want)
	}
}

func TestHTTPDoesNotSupportUDP(t *testing.T) {
	cfg := &config.ProxyOutbound{Name: "h", Type: config.ProtocolHTTP, Server: "127.0.0.1", Port: 8080}
	outbound, err := CreateSingboxOutbound(cfg)
	if err != nil {
		t.Fatalf("create outbound: %v", err)
	}
	if _, err := outbound.ListenPacket(context.Background(), "127.0.0.1:19132"); err == nil {
		t.Fatal("expected HTTP UDP to be unsupported, got nil error")
	}
}

func TestCreateSOCKS5AndHTTPOutbounds(t *testing.T) {
	for _, typ := range []string{config.ProtocolSOCKS5, config.ProtocolHTTP} {
		cfg := &config.ProxyOutbound{Name: "x", Type: typ, Server: "127.0.0.1", Port: 1080}
		if _, err := CreateSingboxOutbound(cfg); err != nil {
			t.Fatalf("CreateSingboxOutbound(%s): %v", typ, err)
		}
		if _, err := CreateSingboxDialer(cfg); err != nil {
			t.Fatalf("CreateSingboxDialer(%s): %v", typ, err)
		}
	}
}

// Ensure the base64 helper matches encoding/base64 for sanity.
func TestBasicAuthEncoding(t *testing.T) {
	got := basicAuth("user", "secret")
	want := "dXNlcjpzZWNyZXQ="
	if got != want {
		t.Fatalf("basicAuth mismatch: got %q want %q", got, want)
	}
}
