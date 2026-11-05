package proxy

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4/jwt"
	"github.com/google/uuid"
	"github.com/sandertv/gophertunnel/minecraft/auth"
	"github.com/sandertv/gophertunnel/minecraft/service"
)

type netherNetIdentityTransport struct {
	ctx     context.Context
	inner   http.RoundTripper
	retryAt *atomic.Int64
}

func (t netherNetIdentityTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if time.Now().UnixNano() < t.retryAt.Load() {
		return nil, errors.New("trusted service cooldown")
	}
	ctx, cancel := context.WithCancel(req.Context())
	stop := context.AfterFunc(t.ctx, cancel)
	if t.ctx.Err() != nil {
		stop()
		cancel()
		return nil, context.Canceled
	}
	// 取消必须覆盖响应体读取，而不只是响应头。
	response, err := t.inner.RoundTrip(req.Clone(ctx))
	if err != nil {
		t.retryAt.Store(time.Now().Add(30 * time.Second).UnixNano())
		stop()
		cancel()
		return nil, err
	}
	if response.StatusCode != http.StatusOK {
		t.retryAt.Store(time.Now().Add(30 * time.Second).UnixNano())
	}
	response.Body = &netherNetIdentityBody{ReadCloser: response.Body, stop: stop, cancel: cancel}
	return response, nil
}

type netherNetIdentityBody struct {
	io.ReadCloser
	stop   func() bool
	cancel context.CancelFunc
}

func (b *netherNetIdentityBody) Close() error {
	defer b.cancel()
	defer b.stop()
	return b.ReadCloser.Close()
}

type netherNetTokenVerifier interface {
	Verify(context.Context, string) (*oidc.IDToken, error)
}

type netherNetIdentityProvider struct {
	ctx           context.Context
	cancel        context.CancelFunc
	mu            sync.Mutex
	verifier      netherNetTokenVerifier
	issuer        string
	initializing  chan struct{}
	retryAt       time.Time
	initialize    func(context.Context) (netherNetTokenVerifier, string, error)
	wg            sync.WaitGroup
	remoteRetryAt atomic.Int64
}

func newNetherNetIdentityProvider(ctx context.Context, client *http.Client) *netherNetIdentityProvider {
	if client == nil {
		client = &http.Client{Timeout: 3 * time.Second}
	} else {
		copy := *client
		client = &copy
		if client.Timeout <= 0 {
			client.Timeout = 3 * time.Second
		}
	}
	life, cancel := context.WithCancel(ctx)
	p := &netherNetIdentityProvider{ctx: life, cancel: cancel}
	transport := client.Transport
	if transport == nil {
		transport = http.DefaultTransport
	}
	client.Transport = netherNetIdentityTransport{life, transport, &p.remoteRetryAt}
	p.initialize = func(ctx context.Context) (netherNetTokenVerifier, string, error) {
		discovery, err := service.Default(auth.WithContextClient(ctx, client))
		if err != nil {
			return nil, "", err
		}
		var env service.AuthorizationEnvironment
		if err := discovery.Environment(&env); err != nil {
			return nil, "", err
		}
		env.HTTPClient = client
		// JWKS 实现保留 WithoutCancel(context)；HTTP transport 另行绑定 provider 生命周期。
		verifier, err := env.VerifierContext(ctx)
		if err != nil {
			return nil, "", err
		}
		return verifier, env.Issuer.JoinPath().String(), nil
	}
	return p
}

func (p *netherNetIdentityProvider) Close() { p.mu.Lock(); p.cancel(); p.mu.Unlock(); p.wg.Wait() }

func (p *netherNetIdentityProvider) tokenVerifier(ctx context.Context) (netherNetTokenVerifier, string, error) {
	p.mu.Lock()
	if p.ctx.Err() != nil {
		p.mu.Unlock()
		return nil, "", context.Canceled
	}
	if p.verifier != nil {
		v, issuer := p.verifier, p.issuer
		p.mu.Unlock()
		return v, issuer, nil
	}
	if time.Now().Before(p.retryAt) {
		p.mu.Unlock()
		return nil, "", errors.New("discovery cooldown")
	}
	if p.initializing == nil {
		done := make(chan struct{})
		p.initializing = done
		p.wg.Add(1)
		go func() {
			defer p.wg.Done()
			v, issuer, err := p.initialize(p.ctx)
			p.mu.Lock()
			defer p.mu.Unlock()
			if err == nil && p.ctx.Err() == nil {
				p.verifier, p.issuer = v, issuer
			} else {
				p.retryAt = time.Now().Add(30 * time.Second)
			}
			p.initializing = nil
			close(done)
		}()
	}
	done := p.initializing
	p.mu.Unlock()
	select {
	case <-ctx.Done():
		return nil, "", ctx.Err()
	case <-p.ctx.Done():
		return nil, "", p.ctx.Err()
	case <-done:
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.verifier == nil {
		return nil, "", errors.New("trusted verifier unavailable")
	}
	return p.verifier, p.issuer, nil
}

func (p *netherNetIdentityProvider) VerifyOffer(ctx context.Context, offer []byte) (netherNetIdentityObservation, error) {
	failure := func(status, reason string) (netherNetIdentityObservation, error) {
		return netherNetIdentityObservation{Status: status, ReasonCode: reason}, nil
	}
	parsed, err := parseNetherNetIdentityOffer(offer)
	if errors.Is(err, errNetherNetIdentityMissing) {
		return failure("missing", "identity_missing")
	}
	if err != nil {
		return failure("invalid", "assertion_malformed")
	}
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()
	stop := context.AfterFunc(p.ctx, cancel)
	defer stop()
	verifier, issuer, err := p.tokenVerifier(ctx)
	if err != nil {
		return failure("unavailable", "trusted_service_unavailable")
	}
	// 域名仅用于比较，绝不作为发现、JWKS 或 HTTP 请求目标。
	if strings.TrimRight(parsed.domain, "/") != strings.TrimRight(issuer, "/") {
		return failure("invalid", "issuer_mismatch")
	}
	token, err := verifier.Verify(ctx, parsed.token)
	if err != nil {
		var networkErr *url.Error
		if errors.As(err, &networkErr) || ctx.Err() != nil || time.Now().UnixNano() < p.remoteRetryAt.Load() {
			return failure("unavailable", "trusted_service_unavailable")
		}
		return failure("invalid", "token_rejected")
	}
	var raw json.RawMessage
	if err := token.Claims(&raw); err != nil {
		return failure("invalid", "claims_malformed")
	}
	var claims struct {
		jwt.Claims
		CPK  json.RawMessage `json:"cpk"`
		Name string          `json:"xname"`
		XUID string          `json:"xid"`
		UUID string          `json:"identity"`
	}
	if err := decodeNetherNetJSON(raw, &claims); err != nil {
		return failure("invalid", "claims_malformed")
	}
	if claims.Expiry == nil || claims.Validate(jwt.Expected{Time: time.Now()}) != nil {
		return failure("invalid", "token_time_invalid")
	}
	key, err := parseNetherNetClaimKey(claims.CPK)
	if err != nil {
		return failure("invalid", "cpk_invalid")
	}
	if verifyNetherNetFingerprintAssertion(parsed, key) != nil {
		return failure("invalid", "fingerprint_mismatch")
	}
	if len(claims.Name) > 128 || strings.ContainsAny(claims.Name, "\x00\r\n") || len(claims.XUID) > 32 {
		return failure("invalid", "claims_malformed")
	}
	for _, c := range claims.XUID {
		if c < '0' || c > '9' {
			return failure("invalid", "claims_malformed")
		}
	}
	id := ""
	if parsedID, err := uuid.Parse(claims.UUID); err == nil && parsedID != uuid.Nil {
		id = parsedID.String()
	}
	return netherNetIdentityObservation{Status: "verified_signaling", DisplayName: claims.Name, XUID: claims.XUID, UUID: id, VerifiedAt: time.Now()}, nil
}
