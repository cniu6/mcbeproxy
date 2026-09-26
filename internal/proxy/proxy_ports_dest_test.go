package proxy

import (
	"net"
	"strconv"
	"testing"
)

func TestParseSocks5UDPDest(t *testing.T) {
	cases := []struct {
		hdr  []byte
		want string
	}{
		{[]byte{0x01, 51, 79, 230, 120, 0x4a, 0xbc}, "51.79.230.120:19132"},
		{append(append([]byte{0x04}, net.ParseIP("2001:db8::1").To16()...), 0x4a, 0xbc), "[2001:db8::1]:19132"},
		{append(append([]byte{0x03, 17}, "play.venitymc.com"...), 0x4a, 0xbc), "play.venitymc.com:19132"},
	}
	for _, c := range cases {
		host, port, ok := parseSocks5UDPDest(c.hdr)
		if !ok || net.JoinHostPort(host, strconv.Itoa(port)) != c.want {
			t.Fatalf("parse %x = %q %d %v, want %s", c.hdr, host, port, ok, c.want)
		}
		if hl, err := socks5UDPHeaderLen(c.hdr); err != nil || hl != len(c.hdr) {
			t.Fatalf("header len %x = %d %v", c.hdr, hl, err)
		}
	}
	if _, _, ok := parseSocks5UDPDest([]byte{0x05, 0, 0}); ok {
		t.Fatal("unknown ATYP accepted")
	}
}
