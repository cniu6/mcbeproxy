package proxy

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"net"
	"testing"
	"time"

	M "github.com/sagernet/sing/common/metadata"
)

func aes128GCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

// TestSSNativeUDPWireFormat checks the single-buffer WriteTo against an
// independent decryption of the Shadowsocks AEAD UDP format, then feeds the
// packet back through ReadFrom (the format is the same in both directions).
func TestSSNativeUDPWireFormat(t *testing.T) {
	server, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer server.Close()
	local, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	key := bytes.Repeat([]byte{7}, 16)
	dest := M.ParseSocksaddr("51.79.230.120:19132")
	c := &ssNativeUDPPacketConn{
		UDPConn:     local,
		serverAddr:  server.LocalAddr().(*net.UDPAddr),
		destination: dest,
		key:         key,
		keySaltLen:  16,
		constructor: aes128GCM,
	}
	defer c.Close()

	payload := append([]byte{0x84}, bytes.Repeat([]byte("mc"), 300)...)
	if n, err := c.WriteTo(payload, nil); err != nil || n != len(payload) {
		t.Fatalf("WriteTo = %d, %v", n, err)
	}
	raw := make([]byte, 4096)
	_ = server.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, from, err := server.ReadFromUDP(raw)
	if err != nil {
		t.Fatalf("server read: %v", err)
	}
	raw = raw[:n]

	// Independent decode: [salt][AEAD(HKDF-SHA1(key, salt, "ss-subkey"), zero nonce, [dest][payload])].
	aead, _ := aes128GCM(ssKdf(key, raw[:16], 16))
	plain, err := aead.Open(nil, make([]byte, aead.NonceSize()), raw[16:], nil)
	if err != nil {
		t.Fatalf("packet does not decrypt: %v", err)
	}
	destLen := M.SocksaddrSerializer.AddrPortLen(dest)
	if !bytes.Equal(plain[destLen:], payload) {
		t.Fatal("decrypted payload mismatch")
	}

	// Server reply uses the same format; ReadFrom must recover the payload.
	if _, err := server.WriteToUDP(raw, from); err != nil {
		t.Fatal(err)
	}
	got := make([]byte, 4096)
	_ = c.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _, err = c.ReadFrom(got)
	if err != nil || !bytes.Equal(got[:n], payload) {
		t.Fatalf("ReadFrom = %d bytes, %v", n, err)
	}
}
