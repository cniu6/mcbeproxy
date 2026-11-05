package proxy

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/pion/sdp/v3"
)

type netherNetIdentityVerifier interface {
	VerifyOffer(context.Context, []byte) (netherNetIdentityObservation, error)
}

type netherNetIdentityObservation struct {
	Status      string
	ReasonCode  string
	DisplayName string
	XUID        string
	UUID        string
	VerifiedAt  time.Time
}

type netherNetFingerprint struct {
	Algorithm string `json:"algorithm"`
	Digest    string `json:"digest"`
}

type netherNetIdentityOffer struct {
	token        string
	signature    string
	domain       string
	fingerprints []netherNetFingerprint
}

var errNetherNetIdentityMissing = errors.New("identity missing")

// 拒绝重复 JSON 键，避免发行方、签名及声明在不同解析器中产生不同解释。
func decodeNetherNetJSON(raw []byte, target any) error {
	d := json.NewDecoder(bytes.NewReader(raw))
	var value func(int) error
	value = func(depth int) error {
		if depth > 16 {
			return errors.New("JSON nesting limit")
		}
		token, err := d.Token()
		if err != nil {
			return err
		}
		delim, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		switch delim {
		case '{':
			seen := make(map[string]bool)
			for d.More() {
				key, err := d.Token()
				if err != nil {
					return err
				}
				k, ok := key.(string)
				if !ok || seen[k] {
					return errors.New("ambiguous JSON key")
				}
				seen[k] = true
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		case '[':
			for d.More() {
				if err := value(depth + 1); err != nil {
					return err
				}
			}
		default:
			return errors.New("invalid JSON delimiter")
		}
		_, err = d.Token()
		return err
	}
	if err := value(0); err != nil {
		return err
	}
	if _, err := d.Token(); err != io.EOF {
		return errors.New("trailing JSON")
	}
	return json.Unmarshal(raw, target)
}

func parseNetherNetIdentityOffer(offer []byte) (netherNetIdentityOffer, error) {
	var result netherNetIdentityOffer
	if len(offer) == 0 || len(offer) > netherNetMaxSDPSize {
		return result, errors.New("invalid SDP size")
	}
	var desc sdp.SessionDescription
	if err := desc.Unmarshal(offer); err != nil {
		return result, errors.New("invalid SDP")
	}
	attrs := append([]sdp.Attribute(nil), desc.Attributes...)
	for _, media := range desc.MediaDescriptions {
		attrs = append(attrs, media.Attributes...)
	}
	identity := ""
	for _, a := range attrs {
		switch a.Key {
		case "identity":
			if identity != "" || a.Value == "" {
				return result, errors.New("ambiguous identity")
			}
			identity = a.Value
		case "fingerprint":
			parts := strings.Fields(a.Value)
			if len(parts) != 2 || len(result.fingerprints) >= 16 {
				return result, errors.New("invalid fingerprints")
			}
			algorithm := strings.ToLower(parts[0])
			size := 0
			switch algorithm {
			case "sha-256":
				size = 32
			case "sha-384":
				size = 48
			case "sha-512":
				size = 64
			default:
				return result, errors.New("unsupported fingerprint")
			}
			digest, err := hex.DecodeString(strings.ReplaceAll(parts[1], ":", ""))
			if err != nil || len(digest) != size || len(parts[1]) != size*3-1 {
				return result, errors.New("invalid fingerprint digest")
			}
			for i := 2; i < len(parts[1]); i += 3 {
				if parts[1][i] != ':' {
					return result, errors.New("invalid fingerprint separator")
				}
			}
			// 与锁定 go-nethernet 版本相同：保留摘要大小写及 SDP 顺序，不只验证首个指纹。
			for _, fp := range result.fingerprints {
				if fp.Algorithm == algorithm {
					return result, errors.New("duplicate fingerprint algorithm")
				}
			}
			result.fingerprints = append(result.fingerprints, netherNetFingerprint{parts[0], parts[1]})
		}
	}
	if identity == "" {
		return result, errNetherNetIdentityMissing
	}
	if len(identity) > 256*1024 || len(result.fingerprints) == 0 {
		return result, errors.New("invalid identity size or fingerprints")
	}
	raw, err := base64.StdEncoding.DecodeString(identity)
	if err != nil {
		return result, errors.New("invalid identity encoding")
	}
	var envelope struct {
		Assertion string `json:"assertion"`
		IDP       struct {
			Domain   string `json:"domain"`
			Protocol string `json:"protocol"`
		} `json:"idp"`
	}
	if err := decodeNetherNetJSON(raw, &envelope); err != nil {
		return result, err
	}
	var assertion struct {
		Token        string `json:"token"`
		Fingerprints string `json:"fingerprints"`
	}
	if err := decodeNetherNetJSON([]byte(envelope.Assertion), &assertion); err != nil {
		return result, err
	}
	if envelope.IDP.Protocol != "default" || envelope.IDP.Domain == "" || len(envelope.IDP.Domain) > 2048 || len(assertion.Token) > 128*1024 || strings.Count(assertion.Token, ".") != 2 || strings.Count(assertion.Fingerprints, ".") != 2 {
		return result, errors.New("invalid assertion")
	}
	result.token, result.signature, result.domain = assertion.Token, assertion.Fingerprints, envelope.IDP.Domain
	return result, nil
}

func verifyNetherNetFingerprintAssertion(offer netherNetIdentityOffer, key *ecdsa.PublicKey) error {
	var b bytes.Buffer
	b.WriteString(`{"fingerprint":[`)
	for i, fp := range offer.fingerprints {
		if i > 0 {
			b.WriteByte(',')
		}
		b.WriteString(`{"algorithm":`)
		b.WriteString(strconv.Quote(fp.Algorithm))
		b.WriteString(`,"digest":`)
		b.WriteString(strconv.Quote(fp.Digest))
		b.WriteByte('}')
	}
	b.WriteString(`]}`)
	signature, err := jose.ParseDetached(offer.signature, b.Bytes(), []jose.SignatureAlgorithm{jose.ES384})
	if err != nil {
		return errors.New("invalid fingerprint assertion")
	}
	if _, err = signature.Verify(key); err != nil {
		return errors.New("fingerprint signature mismatch")
	}
	return nil
}

func parseNetherNetClaimKey(raw json.RawMessage) (*ecdsa.PublicKey, error) {
	var key any
	raw = bytes.TrimSpace(raw)
	if len(raw) == 0 {
		return nil, errors.New("missing cpk")
	}
	if raw[0] == '{' {
		var jwk jose.JSONWebKey
		if err := decodeNetherNetJSON(raw, &jwk); err != nil {
			return nil, err
		}
		if !jwk.IsPublic() || !jwk.Valid() {
			return nil, errors.New("invalid cpk")
		}
		key = jwk.Key
	} else {
		var encoded string
		if err := json.Unmarshal(raw, &encoded); err != nil {
			return nil, err
		}
		der, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			return nil, err
		}
		key, err = x509.ParsePKIXPublicKey(der)
		if err != nil {
			return nil, err
		}
	}
	ec, ok := key.(*ecdsa.PublicKey)
	if !ok || ec.Curve != elliptic.P384() || ec.X == nil || ec.Y == nil || !ec.Curve.IsOnCurve(ec.X, ec.Y) {
		return nil, errors.New("cpk must be public P-384")
	}
	return ec, nil
}
