package proxy

import (
	"strings"
	"testing"

	"github.com/pion/stun/v3"
)

func authenticatedSTUN(t *testing.T, username, password string) []byte {
	t.Helper()
	msg, err := stun.Build(stun.TransactionID, stun.BindingRequest, stun.NewUsername(username), stun.NewShortTermIntegrity(password), stun.Fingerprint)
	if err != nil {
		t.Fatal(err)
	}
	return msg.Raw
}

func iceTestSDP(ufrag, password string) []byte {
	return []byte("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=ice-ufrag:" + ufrag + "\r\na=ice-pwd:" + password + "\r\n")
}

func TestNetherNetICEBindingIntegrity(t *testing.T) {
	b, err := newNetherNetICEBinding(iceTestSDP("client", "client-password"), iceTestSDP("server", "server-password"))
	if err != nil {
		t.Fatal(err)
	}
	if err := b.CheckClientBinding(authenticatedSTUN(t, "server:client", "server-password")); err != nil {
		t.Fatal(err)
	}
	for _, pkt := range [][]byte{stunRequest("server:client"), authenticatedSTUN(t, "server:attacker", "server-password"), authenticatedSTUN(t, "server:client", "wrong"), nil} {
		if b.CheckClientBinding(pkt) == nil {
			t.Fatal("forged STUN accepted")
		}
	}
	invalid := append(iceTestSDP("client", "password"), []byte("a=ice-ufrag:conflict\r\n")...)
	if _, _, err := netherNetICECredentials(invalid); err == nil {
		t.Fatal("conflicting credentials accepted")
	}
	if _, _, err := netherNetICECredentials([]byte(strings.Repeat("x", netherNetMaxSDPSize+1))); err == nil {
		t.Fatal("oversize SDP accepted")
	}
}
