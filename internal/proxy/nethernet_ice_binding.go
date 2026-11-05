package proxy

import (
	"bytes"
	"errors"
	"strings"

	"github.com/pion/sdp/v3"
	"github.com/pion/stun/v3"
)

type netherNetICEBinding struct {
	clientUfrag    string
	serverUfrag    string
	serverPassword string
}

// 每侧仅支持本中继已有的单 application/BUNDLE 传输，冲突凭据不能被最后一行覆盖。
func netherNetICECredentials(raw []byte) (string, string, error) {
	if len(raw) == 0 || len(raw) > netherNetMaxSDPSize {
		return "", "", errors.New("invalid ICE SDP size")
	}
	var desc sdp.SessionDescription
	if err := desc.Unmarshal(raw); err != nil {
		return "", "", errors.New("invalid ICE SDP")
	}
	attrs := append([]sdp.Attribute(nil), desc.Attributes...)
	for _, m := range desc.MediaDescriptions {
		attrs = append(attrs, m.Attributes...)
	}
	ufrag, password := "", ""
	for _, a := range attrs {
		var dst *string
		switch a.Key {
		case "ice-ufrag":
			dst = &ufrag
		case "ice-pwd":
			dst = &password
		default:
			continue
		}
		if *dst != "" && *dst != a.Value {
			return "", "", errors.New("conflicting ICE credentials")
		}
		if a.Value == "" || len(a.Value) > 256 || strings.ContainsAny(a.Value, ": \r\n\t") {
			return "", "", errors.New("invalid ICE credentials")
		}
		*dst = a.Value
	}
	if ufrag == "" || password == "" {
		return "", "", errors.New("missing ICE credentials")
	}
	return ufrag, password, nil
}

func newNetherNetICEBinding(offer, answer []byte) (netherNetICEBinding, error) {
	client, _, err := netherNetICECredentials(offer)
	if err != nil {
		return netherNetICEBinding{}, err
	}
	server, password, err := netherNetICECredentials(answer)
	if err != nil {
		return netherNetICEBinding{}, err
	}
	return netherNetICEBinding{client, server, password}, nil
}

func (b *netherNetICEBinding) CheckClientBinding(packet []byte) error {
	if len(packet) < stunHeaderSize || len(packet) > netherNetRelayPacketSize {
		return errors.New("invalid STUN length")
	}
	msg := &stun.Message{Raw: append([]byte(nil), packet...)}
	if err := msg.Decode(); err != nil || msg.Type != stun.BindingRequest || int(msg.Length)+stunHeaderSize != len(packet) {
		return errors.New("invalid STUN binding")
	}
	usernames, integrities := 0, 0
	afterIntegrity := false
	for _, a := range msg.Attributes {
		if a.Type == stun.AttrUsername {
			usernames++
		}
		if a.Type == stun.AttrMessageIntegrity {
			integrities++
			afterIntegrity = true
			continue
		}
		// 完整性属性之后不能放用于路由的未认证 USERNAME 等属性。
		if afterIntegrity && a.Type != stun.AttrFingerprint {
			return errors.New("unsigned STUN attribute")
		}
	}
	if usernames != 1 || integrities != 1 {
		return errors.New("ambiguous STUN authentication")
	}
	var username stun.Username
	if err := username.GetFrom(msg); err != nil || !bytes.Equal(username, []byte(b.serverUfrag+":"+b.clientUfrag)) {
		return errors.New("ICE session mismatch")
	}
	return stun.NewShortTermIntegrity(b.serverPassword).Check(msg)
}
