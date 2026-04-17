// Package proxy tests raw_udp MCBE Login packet parsing for player name /
// UUID / XUID extraction. Regression coverage for the historical bug where
// modern clients sending Login with compression ID 0xff (no compression,
// the default before the NetworkSettings negotiation) had their identity
// silently dropped because parseLoginPacket only handled 0x00/0x01.
package proxy

import (
	"bytes"
	"compress/flate"
	"encoding/binary"
	"encoding/json"
	"testing"

	"github.com/golang-jwt/jwt/v4"
	"github.com/golang/snappy"
)

const (
	testPlayerName = "TestPlayer123"
	testPlayerUUID = "12345678-1234-1234-1234-1234567890ab"
	testPlayerXUID = "2535400000000000"
)

// buildChainJWT returns an unsigned JWT payload containing an extraData
// block like MCBE's identity chain. We use the "none" alg because
// parseLoginPacket uses ParseUnverified - signature bytes are ignored.
func buildChainJWT(t *testing.T, displayName, uuid, xuid string) string {
	t.Helper()
	type extra struct {
		DisplayName string `json:"displayName"`
		Identity    string `json:"identity"`
		XUID        string `json:"XUID"`
	}
	claims := jwt.MapClaims{
		"extraData": extra{DisplayName: displayName, Identity: uuid, XUID: xuid},
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	s, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign chain jwt: %v", err)
	}
	return s
}

// buildClientDataJWT returns an unsigned JWT with a ThirdPartyName claim,
// mirroring the raw token appended after the chain in ConnectionRequest.
func buildClientDataJWT(t *testing.T, thirdPartyName string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"ThirdPartyName": thirdPartyName,
		"SelfSignedId":   "00000000-0000-0000-0000-000000000001",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	s, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign client-data jwt: %v", err)
	}
	return s
}

// buildOIDCJWT returns an unsigned OIDC multiplayer-token JWT that carries
// the player identity in the xname/xid claims (the post-2024 format).
func buildOIDCJWT(t *testing.T, displayName, xuid string) string {
	t.Helper()
	claims := jwt.MapClaims{
		"xname": displayName,
		"xid":   xuid,
		"mid":   "playfab-mid-01",
	}
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, claims)
	s, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign oidc jwt: %v", err)
	}
	return s
}

// buildConnectionRequestBytes assembles the inner ConnectionRequest blob
// from raw JSON chainData and optional rawToken (ClientData JWT).
func buildConnectionRequestBytes(chainData, rawToken []byte) []byte {
	var buf bytes.Buffer
	_ = binary.Write(&buf, binary.LittleEndian, int32(len(chainData)))
	buf.Write(chainData)
	_ = binary.Write(&buf, binary.LittleEndian, int32(len(rawToken)))
	buf.Write(rawToken)
	return buf.Bytes()
}

// buildLoginBatch wraps connReq inside a Login(0x01) packet inside a MCBE
// packet batch (varuint length + varuint packet-id + protocol int32 BE +
// varuint connreq length + connreq bytes).
func buildLoginBatch(connReq []byte) []byte {
	var inner bytes.Buffer
	writeVaruint32(&inner, 0x01) // Login packet ID (shared helper from passthrough_proxy.go)
	_ = binary.Write(&inner, binary.BigEndian, int32(712))
	writeVaruint32(&inner, uint32(len(connReq)))
	inner.Write(connReq)

	var batch bytes.Buffer
	writeVaruint32(&batch, uint32(inner.Len()))
	batch.Write(inner.Bytes())
	return batch.Bytes()
}

// wrapGamePacket prepends the MCBE 0xfe game-packet wrapper and an optional
// compression byte, then applies the compression (or 'none' semantics).
// When compressionID is the sentinel -1 the compression byte is omitted
// entirely (pre-1.19.30 legacy: raw deflate batch directly after 0xfe).
func wrapGamePacket(t *testing.T, compressionID int, batch []byte) []byte {
	t.Helper()

	var payload []byte
	switch compressionID {
	case -1: // legacy: raw deflate, no compression byte
		var buf bytes.Buffer
		w, err := flate.NewWriter(&buf, flate.DefaultCompression)
		if err != nil {
			t.Fatalf("flate writer: %v", err)
		}
		_, _ = w.Write(batch)
		_ = w.Close()
		payload = buf.Bytes()
		return append([]byte{0xfe}, payload...)
	case 0x00: // deflate
		var buf bytes.Buffer
		w, err := flate.NewWriter(&buf, flate.DefaultCompression)
		if err != nil {
			t.Fatalf("flate writer: %v", err)
		}
		_, _ = w.Write(batch)
		_ = w.Close()
		payload = buf.Bytes()
	case 0x01: // snappy
		payload = snappy.Encode(nil, batch)
	case 0xff: // none
		payload = batch
	default:
		t.Fatalf("unsupported compression id %x", compressionID)
	}
	return append([]byte{0xfe, byte(compressionID)}, payload...)
}

// buildStandardChainJSON assembles the canonical modern wire format:
// {"AuthenticationType":0,"Certificate":"{\"chain\":[...]}"} containing
// the provided JWTs.
func buildStandardChainJSON(t *testing.T, chainJWTs []string) []byte {
	t.Helper()
	inner, err := json.Marshal(map[string]any{"chain": chainJWTs})
	if err != nil {
		t.Fatalf("marshal inner: %v", err)
	}
	outer, err := json.Marshal(map[string]any{
		"AuthenticationType": 0,
		"Certificate":        string(inner),
	})
	if err != nil {
		t.Fatalf("marshal outer: %v", err)
	}
	return outer
}

// buildDirectChainJSON assembles the legacy {"chain":[...]} wire format.
func buildDirectChainJSON(t *testing.T, chainJWTs []string) []byte {
	t.Helper()
	payload, err := json.Marshal(map[string]any{"chain": chainJWTs})
	if err != nil {
		t.Fatalf("marshal direct chain: %v", err)
	}
	return payload
}

// buildOIDCChainJSON assembles the 2024+ authed wire format with a
// separate Token field carrying the OIDC multiplayer token. The chain
// itself can still be non-empty but we test the case where identity must
// be read from Token.
func buildOIDCChainJSON(t *testing.T, oidcToken string, selfSignedChain []string) []byte {
	t.Helper()
	inner, err := json.Marshal(map[string]any{"chain": selfSignedChain})
	if err != nil {
		t.Fatalf("marshal inner: %v", err)
	}
	outer, err := json.Marshal(map[string]any{
		"AuthenticationType": 0,
		"Certificate":        string(inner),
		"Token":              oidcToken,
	})
	if err != nil {
		t.Fatalf("marshal outer: %v", err)
	}
	return outer
}

// TestParseLoginPacket_Compression covers every compression ID MCBE has
// shipped for the Login packet, including the historically broken 0xff
// (no compression) path and the legacy pre-1.19.30 format that omits the
// compression byte altogether.
func TestParseLoginPacket_Compression(t *testing.T) {
	chainJWT := buildChainJWT(t, testPlayerName, testPlayerUUID, testPlayerXUID)
	chainData := buildStandardChainJSON(t, []string{chainJWT})
	connReq := buildConnectionRequestBytes(chainData, []byte(buildClientDataJWT(t, "ignored")))
	batch := buildLoginBatch(connReq)

	cases := []struct {
		name          string
		compressionID int
	}{
		{"flate 0x00", 0x00},
		{"snappy 0x01", 0x01},
		{"none 0xff (modern pre-NetworkSettings)", 0xff},
		{"legacy pre-1.19.30 (no compression byte)", -1},
	}

	proxy := &RawUDPProxy{}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			wrapped := wrapGamePacket(t, tc.compressionID, batch)
			name, uuid, xuid := proxy.parseLoginPacket(wrapped)
			if name != testPlayerName {
				t.Fatalf("DisplayName = %q, want %q", name, testPlayerName)
			}
			if uuid != testPlayerUUID {
				t.Fatalf("UUID = %q, want %q", uuid, testPlayerUUID)
			}
			if xuid != testPlayerXUID {
				t.Fatalf("XUID = %q, want %q", xuid, testPlayerXUID)
			}
		})
	}
}

// TestParseConnectionRequest_StandardChain verifies the canonical modern
// format: {"Certificate": "{\"chain\":[...]}"}.
func TestParseConnectionRequest_StandardChain(t *testing.T) {
	chainJWT := buildChainJWT(t, testPlayerName, testPlayerUUID, testPlayerXUID)
	chainData := buildStandardChainJSON(t, []string{chainJWT})
	connReq := buildConnectionRequestBytes(chainData, []byte(buildClientDataJWT(t, "ignored")))

	proxy := &RawUDPProxy{}
	name, uuid, xuid := proxy.parseConnectionRequest(connReq)
	if name != testPlayerName || uuid != testPlayerUUID || xuid != testPlayerXUID {
		t.Fatalf("got name=%q uuid=%q xuid=%q; want %q %q %q",
			name, uuid, xuid, testPlayerName, testPlayerUUID, testPlayerXUID)
	}
}

// TestParseConnectionRequest_DirectChain verifies legacy {"chain":[...]}
// without the outer Certificate wrapper (1-element offline logins and
// some third-party clients).
func TestParseConnectionRequest_DirectChain(t *testing.T) {
	chainJWT := buildChainJWT(t, testPlayerName, testPlayerUUID, testPlayerXUID)
	chainData := buildDirectChainJSON(t, []string{chainJWT})
	connReq := buildConnectionRequestBytes(chainData, []byte(buildClientDataJWT(t, "ignored")))

	proxy := &RawUDPProxy{}
	name, uuid, xuid := proxy.parseConnectionRequest(connReq)
	if name != testPlayerName || uuid != testPlayerUUID || xuid != testPlayerXUID {
		t.Fatalf("got name=%q uuid=%q xuid=%q; want %q %q %q",
			name, uuid, xuid, testPlayerName, testPlayerUUID, testPlayerXUID)
	}
}

// TestParseConnectionRequest_OIDCToken verifies the 2024+ flow where the
// chain JWTs don't carry extraData.displayName but the outer blob includes
// a Token field with an OIDC multiplayer token (xname + xid).
func TestParseConnectionRequest_OIDCToken(t *testing.T) {
	// Self-signed chain with no displayName - simulates a chain whose
	// identity JWT failed to parse or was stripped.
	placeholderJWT := buildChainJWT(t, "", "", "")
	oidcToken := buildOIDCJWT(t, testPlayerName, testPlayerXUID)
	chainData := buildOIDCChainJSON(t, oidcToken, []string{placeholderJWT})
	connReq := buildConnectionRequestBytes(chainData, []byte(buildClientDataJWT(t, "ignored")))

	proxy := &RawUDPProxy{}
	name, _, xuid := proxy.parseConnectionRequest(connReq)
	if name != testPlayerName {
		t.Fatalf("DisplayName = %q, want %q (OIDC xname)", name, testPlayerName)
	}
	if xuid != testPlayerXUID {
		t.Fatalf("XUID = %q, want %q (OIDC xid)", xuid, testPlayerXUID)
	}
}

// TestParseConnectionRequest_ThirdPartyNameFallback verifies that when the
// chain is entirely opaque (e.g. all JWTs unparsable) we still recover the
// DisplayName from the ClientData JWT's ThirdPartyName claim. This is the
// only identity available on some China-Edition / custom launcher builds.
func TestParseConnectionRequest_ThirdPartyNameFallback(t *testing.T) {
	// Use a chain with garbage JWT - parseConnectionRequest should not
	// yield a DisplayName from it.
	garbageChain := []string{"not.a.real.jwt"}
	chainData, err := json.Marshal(map[string]any{
		"AuthenticationType": 0,
		"Certificate":        string(buildDirectChainJSON(t, garbageChain)),
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	rawToken := buildClientDataJWT(t, "OfflinePlayer7")
	connReq := buildConnectionRequestBytes(chainData, []byte(rawToken))

	proxy := &RawUDPProxy{}
	name, _, _ := proxy.parseConnectionRequest(connReq)
	if name != "OfflinePlayer7" {
		t.Fatalf("DisplayName = %q, want %q via ThirdPartyName fallback", name, "OfflinePlayer7")
	}
}

// TestDecodeGamePacketBatch verifies decodeGamePacketBatch tolerates every
// compression format including the legacy pre-1.19.30 raw-deflate layout.
func TestDecodeGamePacketBatch(t *testing.T) {
	payload := []byte("hello-mcbe-batch-payload-for-decompression-test")
	proxy := &RawUDPProxy{}

	for _, tc := range []struct {
		name string
		id   int
	}{
		{"deflate 0x00", 0x00},
		{"snappy 0x01", 0x01},
		{"none 0xff", 0xff},
		{"legacy no-byte", -1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			wrapped := wrapGamePacket(t, tc.id, payload)

			// For the legacy case there's no compression byte so we feed
			// (0xff) as the dummy compressionID and let the legacy
			// fallback in decodeGamePacketBatch pick up raw deflate.
			var compID byte = 0x00
			if tc.id >= 0 {
				compID = byte(tc.id)
			} else {
				// Legacy: data[1] is first byte of deflate stream, which
				// is unpredictable but is NOT 0x00/0x01/0xff in general.
				// Pick a compID that intentionally mismatches so we
				// exercise the legacy fallback branch.
				compID = wrapped[1]
			}
			got := proxy.decodeGamePacketBatch(compID, wrapped)
			if !bytes.Equal(got, payload) {
				t.Fatalf("decoded mismatch: got %q want %q", got, payload)
			}
		})
	}
}

// TestParseLoginPacket_RejectsNonGamePacket verifies we still return empty
// identity (and don't crash) for packets that look nothing like a Login.
func TestParseLoginPacket_RejectsNonGamePacket(t *testing.T) {
	proxy := &RawUDPProxy{}
	if n, u, x := proxy.parseLoginPacket(nil); n != "" || u != "" || x != "" {
		t.Fatalf("nil should yield empty identity, got %q %q %q", n, u, x)
	}
	if n, u, x := proxy.parseLoginPacket([]byte{0xab, 0xcd}); n != "" || u != "" || x != "" {
		t.Fatalf("short garbage should yield empty identity, got %q %q %q", n, u, x)
	}
	if n, u, x := proxy.parseLoginPacket([]byte{0x00, 0xff, 0x01, 0x02}); n != "" || u != "" || x != "" {
		t.Fatalf("non-game-packet-header should yield empty identity, got %q %q %q", n, u, x)
	}
}

// TestExtractIdentityFromOIDCToken checks the standalone OIDC parser with
// canonical and malformed inputs.
func TestExtractIdentityFromOIDCToken(t *testing.T) {
	proxy := &RawUDPProxy{}

	// Valid OIDC token roundtrips xname/xid.
	tok := buildOIDCJWT(t, "OidcName", "7777")
	n, _, x := proxy.extractIdentityFromOIDCToken(tok)
	if n != "OidcName" || x != "7777" {
		t.Fatalf("OIDC roundtrip failed: name=%q xuid=%q", n, x)
	}

	// Malformed token must return empty, not panic.
	n, _, x = proxy.extractIdentityFromOIDCToken("not-a-jwt")
	if n != "" || x != "" {
		t.Fatalf("malformed OIDC should yield empty: got name=%q xuid=%q", n, x)
	}
}
