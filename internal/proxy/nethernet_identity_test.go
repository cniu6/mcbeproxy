package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/sandertv/gophertunnel/minecraft/service"
)

const identityTestFingerprint = "AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99"

func identityTestOffer(t *testing.T, issuer string, signer jose.Signer, key *ecdsa.PrivateKey, modify func(map[string]any)) []byte {
	t.Helper()
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	claims := map[string]any{"iss": issuer, "aud": "api://auth-minecraft-services/multiplayer", "exp": time.Now().Add(time.Hour).Unix(), "iat": time.Now().Add(-time.Minute).Unix(), "cpk": base64.StdEncoding.EncodeToString(der), "xname": "Alice", "xid": "123456789"}
	if modify != nil {
		modify(claims)
	}
	raw, _ := json.Marshal(claims)
	signed, err := signer.Sign(raw)
	if err != nil {
		t.Fatal(err)
	}
	token, err := signed.CompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	fpSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.ES384, Key: key}, nil)
	if err != nil {
		t.Fatal(err)
	}
	fp, err := fpSigner.Sign([]byte(`{"fingerprint":[{"algorithm":"sha-256","digest":"` + identityTestFingerprint + `"}]}`))
	if err != nil {
		t.Fatal(err)
	}
	detached, err := fp.DetachedCompactSerialize()
	if err != nil {
		t.Fatal(err)
	}
	assertion, _ := json.Marshal(map[string]string{"token": token, "fingerprints": detached})
	envelope, _ := json.Marshal(map[string]any{"assertion": string(assertion), "idp": map[string]string{"domain": issuer, "protocol": "default"}})
	return []byte("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\na=identity:" + base64.StdEncoding.EncodeToString(envelope) + "\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=fingerprint:sha-256 " + identityTestFingerprint + "\r\n")
}

func TestNetherNetIdentityLocalIssuer(t *testing.T) {
	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var jwksCalls atomic.Int32
	var currentKey atomic.Pointer[rsa.PublicKey]
	currentKey.Store(&issuerKey.PublicKey)
	var currentKeyID atomic.Int32
	currentKeyID.Store(1)
	var issuer string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if strings.Contains(r.URL.Path, "openid-configuration") {
			json.NewEncoder(w).Encode(map[string]any{"issuer": issuer, "jwks_uri": strings.TrimRight(issuer, "/") + "/keys", "id_token_signing_alg_values_supported": []string{"RS256"}})
			return
		}
		if r.URL.Path != "/keys" {
			http.NotFound(w, r)
			return
		}
		jwksCalls.Add(1)
		json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{{Key: currentKey.Load(), KeyID: fmt.Sprint(currentKeyID.Load()), Algorithm: "RS256", Use: "sig", CertificateThumbprintSHA1: make([]byte, 20)}}})
	}))
	defer server.Close()
	issuer = server.URL + "/"
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: issuerKey}, (&jose.SignerOptions{}).WithHeader("kid", "1"))
	if err != nil {
		t.Fatal(err)
	}
	p := newNetherNetIdentityProvider(context.Background(), server.Client())
	defer p.Close()
	var initialized atomic.Int32
	p.initialize = func(ctx context.Context) (netherNetTokenVerifier, string, error) {
		initialized.Add(1)
		u, _ := serverURL(issuer)
		env := &service.AuthorizationEnvironment{Issuer: u, HTTPClient: server.Client(), KeyRefreshInterval: time.Millisecond}
		v, err := env.VerifierContext(ctx)
		return v, issuer, err
	}
	valid := identityTestOffer(t, issuer, signer, key, nil)
	var wg sync.WaitGroup
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			got, err := p.VerifyOffer(context.Background(), valid)
			if err != nil || got.Status != "verified_signaling" || got.DisplayName != "Alice" || got.XUID != "123456789" {
				t.Errorf("valid observation=%+v err=%v", got, err)
			}
		}()
	}
	wg.Wait()
	if initialized.Load() != 1 || jwksCalls.Load() != 1 {
		t.Fatalf("uncached initialization=%d jwks=%d", initialized.Load(), jwksCalls.Load())
	}
	for _, tc := range []struct {
		name   string
		modify func(map[string]any)
	}{
		{"expired", func(c map[string]any) { c["exp"] = time.Now().Add(-time.Hour).Unix() }},
		{"audience", func(c map[string]any) { c["aud"] = "wrong" }},
		{"issuer", func(c map[string]any) { c["iss"] = "https://untrusted.invalid/" }},
		{"not_yet_valid", func(c map[string]any) { c["nbf"] = time.Now().Add(time.Hour).Unix() }},
		{"bad_cpk", func(c map[string]any) { c["cpk"] = "invalid" }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _ := p.VerifyOffer(context.Background(), identityTestOffer(t, issuer, signer, key, tc.modify))
			if got.Status != "invalid" || got.DisplayName != "" {
				t.Fatalf("accepted: %+v", got)
			}
		})
	}
	noName, _ := p.VerifyOffer(context.Background(), identityTestOffer(t, issuer, signer, key, func(c map[string]any) { delete(c, "xname") }))
	if noName.Status != "verified_signaling" || noName.DisplayName != "" {
		t.Fatalf("invented name: %+v", noName)
	}
	rotated, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	currentKey.Store(&rotated.PublicKey)
	currentKeyID.Store(2)
	rotatedSigner, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: rotated}, (&jose.SignerOptions{}).WithHeader("kid", "2"))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(2 * time.Millisecond)
	if observation, _ := p.VerifyOffer(context.Background(), identityTestOffer(t, issuer, rotatedSigner, key, nil)); observation.Status != "verified_signaling" || jwksCalls.Load() != 2 {
		t.Fatalf("JWKS rotation failed: %+v requests=%d", observation, jwksCalls.Load())
	}
	// 后续篡改测试使用当前发行方密钥，不能让旧 kid 的失败掩盖断言错误。
	signer = rotatedSigner
	valid = identityTestOffer(t, issuer, signer, key, nil)
	changed := []byte(strings.Replace(string(valid), "a=fingerprint:sha-256 AA:", "a=fingerprint:sha-256 AB:", 1))
	got, _ := p.VerifyOffer(context.Background(), changed)
	if got.Status != "invalid" || got.DisplayName != "" {
		t.Fatal("changed fingerprint accepted")
	}
	missing, _ := p.VerifyOffer(context.Background(), []byte("v=0\r\no=- 1 1 IN IP4 127.0.0.1\r\ns=-\r\nt=0 0\r\n"))
	if missing.Status != "missing" {
		t.Fatalf("missing=%+v", missing)
	}
	for _, raw := range [][]byte{nil, []byte(strings.Repeat("x", netherNetMaxSDPSize+1)), append(append([]byte(nil), valid...), []byte("a=identity:duplicate\r\n")...), append(append([]byte(nil), valid...), []byte("a=fingerprint:sha-256 "+identityTestFingerprint+"\r\n")...)} {
		got, _ := p.VerifyOffer(context.Background(), raw)
		if got.Status != "invalid" {
			t.Fatalf("malformed accepted: %s", got.Status)
		}
	}
	if decodeNetherNetJSON([]byte(`{"cpk":"a","cpk":"b"}`), &map[string]any{}) == nil {
		t.Fatal("duplicate JSON accepted")
	}
	// 增加第二个有效指纹但保留首个签名时必须拒绝，不能只验证第一项。
	multi := append(append([]byte(nil), valid...), []byte("a=fingerprint:sha-384 "+strings.TrimSuffix(strings.Repeat("AA:", 48), ":")+"\r\n")...)
	if observed, _ := p.VerifyOffer(context.Background(), multi); observed.Status != "invalid" {
		t.Fatal("unsigned second fingerprint accepted")
	}
	// 断言中任意域名只可被比较，不能变成发现或 JWKS 请求目标。
	parsed, err := parseNetherNetIdentityOffer(valid)
	if err != nil {
		t.Fatal(err)
	}
	before := jwksCalls.Load()
	parsed.domain = "http://127.0.0.1:1/"
	assertion, _ := json.Marshal(map[string]string{"token": parsed.token, "fingerprints": parsed.signature})
	envelope, _ := json.Marshal(map[string]any{"assertion": string(assertion), "idp": map[string]string{"domain": parsed.domain, "protocol": "default"}})
	start := strings.Index(string(valid), "a=identity:")
	end := strings.Index(string(valid)[start:], "\r\n") + start
	ssrf := string(valid[:start]) + "a=identity:" + base64.StdEncoding.EncodeToString(envelope) + string(valid[end:])
	if observed, _ := p.VerifyOffer(context.Background(), []byte(ssrf)); observed.Status != "invalid" || jwksCalls.Load() != before {
		t.Fatal("untrusted issuer caused network lookup")
	}
}
