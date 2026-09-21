package proxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"mcpeserverproxy/internal/acl"
	"mcpeserverproxy/internal/auth"
	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/logger"
	"mcpeserverproxy/internal/session"

	"github.com/df-mc/go-nethernet"
	"github.com/df-mc/go-nethernet/endpoint"
	"github.com/pion/webrtc/v4"
	"github.com/sandertv/gophertunnel/minecraft"
)

// NetherNetProxy terminates NetherNet on both sides of the proxy. It is kept
// separate from RawUDPProxy because NetherNet needs HTTPS signaling and WebRTC.
type NetherNetProxy struct {
	serverID    string
	config      *config.ServerConfig
	sessionMgr  *session.SessionManager
	listener    *minecraft.Listener
	signaling   *endpoint.Handler
	closed      atomic.Bool
	wg          sync.WaitGroup
	aclManager  *acl.ACLManager
	active      atomic.Int64
	identity    *nethernet.Identity
	authManager *auth.XboxAuthManager
	outboundMgr OutboundManager
}

func NewNetherNetProxy(serverID string, cfg *config.ServerConfig, sessionMgr *session.SessionManager) *NetherNetProxy {
	return &NetherNetProxy{serverID: serverID, config: cfg, sessionMgr: sessionMgr}
}

func (p *NetherNetProxy) Start() error {
	if p.config == nil {
		return fmt.Errorf("nethernet: server config is nil")
	}
	if err := p.config.Validate(); err != nil {
		return err
	}
	if p.config.GetProxyMode() != config.ProxyModeNetherNet {
		return fmt.Errorf("nethernet: proxy_mode must be %q", config.ProxyModeNetherNet)
	}
	identityPath := strings.TrimSpace(p.config.NetherNetIdentityFile)
	if identityPath == "" {
		identityPath = filepath.Join("data", "nethernet", p.serverID+".pem")
	}
	identity, err := loadOrCreateNetherNetIdentity(identityPath)
	if err != nil {
		return err
	}
	if p.config.XboxAuthEnabled {
		p.authManager = auth.NewXboxAuthManager(p.config.XboxTokenPath)
		if err := p.authManager.Authenticate(context.Background()); err != nil {
			return fmt.Errorf("Xbox Live authentication failed: %w", err)
		}
	}
	iceServers := make([]nethernet.ICEServer, 0, len(p.config.NetherNetICEServers))
	for _, server := range p.config.NetherNetICEServers {
		iceServers = append(iceServers, nethernet.ICEServer{Username: server.Username, Password: server.Password, URLs: server.URLs})
	}
	credentials := func(context.Context) (*nethernet.Credentials, error) {
		return &nethernet.Credentials{ICEServers: iceServers}, nil
	}
	handler, err := (endpoint.HandlerConfig{Credentials: credentials}).ServeTLS(
		p.config.NetherNetListenAddr,
		p.config.NetherNetCertFile,
		p.config.NetherNetKeyFile,
	)
	if err != nil {
		return fmt.Errorf("nethernet signaling: %w", err)
	}

	policy := webrtc.ICETransportPolicyAll
	if strings.EqualFold(p.config.NetherNetICEGatherPolicy, "relay") {
		policy = webrtc.ICETransportPolicyRelay
	}
	network := minecraft.NetherNet{
		Signaling: handler,
		ListenConfig: nethernet.ListenConfig{
			AllowAnonymous:      p.config.NetherNetAllowAnonymous,
			IssueServerIdentity: func(context.Context) (*nethernet.Identity, error) { return identity, nil },
			ICEGatherPolicy:     policy,
			// endpoint.Handler uses one HTTP request/response and rejects trickle candidates.
			DisableTrickleICE: true,
		},
	}
	listenerCfg := minecraft.ListenConfig{
		StatusProvider:         minecraft.NewStatusProvider(p.config.Name, "Survival"),
		AuthenticationDisabled: !p.config.XboxAuthEnabled,
	}
	listener, err := listenerCfg.ListenNetwork(network, handler.NetworkID())
	if err != nil {
		_ = handler.Close()
		return fmt.Errorf("nethernet listener: %w", err)
	}

	p.signaling = handler
	p.listener = listener
	p.identity = identity
	p.closed.Store(false)
	logger.Info("NetherNet proxy started: id=%s, signaling=%s, upstream=%s", p.serverID, p.config.NetherNetListenAddr, p.config.NetherNetUpstream)
	return nil
}

func (p *NetherNetProxy) SetACLManager(aclManager *acl.ACLManager) {
	p.aclManager = aclManager
}

func (p *NetherNetProxy) SetOutboundManager(outboundMgr OutboundManager) {
	p.outboundMgr = outboundMgr
}

func (p *NetherNetProxy) Listen(ctx context.Context) error {
	if p.listener == nil {
		return fmt.Errorf("nethernet listener not started")
	}
	for {
		conn, err := p.listener.Accept()
		if err != nil {
			if p.closed.Load() || ctx.Err() != nil {
				return nil
			}
			return err
		}
		p.wg.Add(1)
		go p.handleConnection(ctx, conn.(*minecraft.Conn))
	}
}

func (p *NetherNetProxy) handleConnection(ctx context.Context, clientConn *minecraft.Conn) {
	defer p.wg.Done()
	defer clientConn.Close()
	clientData := clientConn.ClientData()
	identityData := clientConn.IdentityData()
	clientAddr := clientConn.RemoteAddr().String()
	playerName := identityData.DisplayName
	p.active.Add(1)
	defer p.active.Add(-1)

	if p.aclManager != nil {
		allowed, reason, dbErr := p.aclManager.CheckAccessWithError(playerName, p.config.GetACLServerID())
		if dbErr != nil {
			logger.LogACLCheckError(playerName, p.config.GetACLServerID(), dbErr)
		}
		if !allowed {
			logger.LogAccessDenied(playerName, p.config.GetACLServerID(), clientAddr, reason)
			return
		}
	}

	var sess *session.Session
	if p.sessionMgr != nil {
		sess, _ = p.sessionMgr.GetOrCreate(clientAddr, p.serverID)
		if sess != nil {
			defer p.sessionMgr.Remove(clientAddr)
			sess.SetPlayerInfoWithXUID(identityData.Identity, playerName, identityData.XUID)
		}
	}

	clientConfig := endpoint.ClientConfig{Credentials: func(context.Context) (*nethernet.Credentials, error) {
		iceServers := make([]nethernet.ICEServer, 0, len(p.config.NetherNetICEServers))
		for _, server := range p.config.NetherNetICEServers {
			iceServers = append(iceServers, nethernet.ICEServer{Username: server.Username, Password: server.Password, URLs: server.URLs})
		}
		return &nethernet.Credentials{ICEServers: iceServers}, nil
	}}
	if dialer := p.signalingDialer(ctx); dialer != nil {
		clientConfig.HTTPClient = &http.Client{Transport: &http.Transport{DialContext: dialer.DialContext}, Timeout: 20 * time.Second}
	}
	client := clientConfig.New()
	netherDialer := nethernet.Dialer{DisableTrickleICE: true}
	if strings.EqualFold(p.config.NetherNetICEGatherPolicy, "relay") {
		netherDialer.ICEGatherPolicy = webrtc.ICETransportPolicyRelay
	}
	dialer := minecraft.Dialer{ClientData: clientData, IdentityData: identityData}
	if p.authManager != nil {
		dialer.TokenSource = p.authManager.GetTokenSource()
	}
	remote, err := dialer.DialContextNetwork(ctx, minecraft.NetherNet{
		Signaling: client,
		Dialer:    netherDialer,
	}, p.config.NetherNetUpstream)
	if err != nil {
		logger.Error("NetherNet upstream dial failed: server=%s player=%s err=%v", p.serverID, playerName, err)
		return
	}
	defer remote.Close()

	spawnErr := make(chan error, 2)
	go func() { spawnErr <- clientConn.StartGame(remote.GameData()) }()
	go func() { spawnErr <- remote.DoSpawn() }()
	for i := 0; i < 2; i++ {
		if err := <-spawnErr; err != nil {
			logger.Error("NetherNet spawn failed: server=%s player=%s err=%v", p.serverID, playerName, err)
			return
		}
	}

	connCtx, cancel := context.WithCancel(ctx)
	var closeOnce sync.Once
	stop := func() {
		closeOnce.Do(func() {
			cancel()
			_ = clientConn.Close()
			_ = remote.Close()
		})
	}
	defer stop()
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for {
			pk, err := clientConn.ReadPacket()
			if err != nil {
				stop()
				return
			}
			if sess != nil {
				sess.AddBytesUpAndUpdateLastSeen(1)
			}
			if err := remote.WritePacket(pk); err != nil {
				stop()
				return
			}
			select {
			case <-connCtx.Done():
				return
			default:
			}
		}
	}()
	go func() {
		defer wg.Done()
		for {
			pk, err := remote.ReadPacket()
			if err != nil {
				stop()
				return
			}
			if sess != nil {
				sess.AddBytesDownAndUpdateLastSeen(1)
			}
			if err := clientConn.WritePacket(pk); err != nil {
				stop()
				return
			}
			select {
			case <-connCtx.Done():
				return
			default:
			}
		}
	}()
	wg.Wait()
}

func (p *NetherNetProxy) Stop() error {
	if p.closed.Swap(true) {
		return nil
	}
	if p.listener != nil {
		_ = p.listener.Close()
	}
	if p.signaling != nil {
		_ = p.signaling.Close()
	}
	p.wg.Wait()
	return nil
}

func (p *NetherNetProxy) GetActiveClientCount() int {
	return int(p.active.Load())
}

func (p *NetherNetProxy) UpdateConfig(cfg *config.ServerConfig) {
	p.config = cfg
}

func loadOrCreateNetherNetIdentity(path string) (*nethernet.Identity, error) {
	if strings.TrimSpace(path) == "" {
		key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
		if err != nil {
			return nil, fmt.Errorf("nethernet identity: generate key: %w", err)
		}
		return nethernet.GenerateServerIdentity(key, "self")
	}
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block == nil {
			return nil, fmt.Errorf("nethernet identity: invalid PEM file %s", path)
		}
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("nethernet identity: parse key: %w", err)
		}
		privateKey, ok := key.(*ecdsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("nethernet identity: key is not ECDSA")
		}
		return nethernet.GenerateServerIdentity(privateKey, "self")
	} else if !os.IsNotExist(err) {
		return nil, fmt.Errorf("nethernet identity: read %s: %w", path, err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("nethernet identity: generate key: %w", err)
	}
	if dir := filepath.Dir(path); dir != "." {
		if err := os.MkdirAll(dir, 0700); err != nil {
			return nil, fmt.Errorf("nethernet identity: create directory: %w", err)
		}
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("nethernet identity: marshal key: %w", err)
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}), 0600); err != nil {
		return nil, fmt.Errorf("nethernet identity: save key: %w", err)
	}
	return nethernet.GenerateServerIdentity(key, "self")
}

type signalingTCPDialer interface {
	DialContext(ctx context.Context, network, address string) (net.Conn, error)
}

func (p *NetherNetProxy) signalingDialer(ctx context.Context) signalingTCPDialer {
	if p.outboundMgr == nil || strings.TrimSpace(p.config.ProxyOutbound) == "" || strings.EqualFold(strings.TrimSpace(p.config.ProxyOutbound), "direct") {
		return nil
	}
	if provider, ok := p.outboundMgr.(interface {
		DialTCPContext(context.Context, string, string) (net.Conn, error)
	}); ok {
		return signalingDialerFunc(func(ctx context.Context, network, address string) (net.Conn, error) {
			return provider.DialTCPContext(ctx, p.config.ProxyOutbound, address)
		})
	}
	logger.Warn("NetherNet signaling outbound is configured but TCP dial injection is unavailable; using direct HTTP: node=%s", p.config.ProxyOutbound)
	return nil
}

type signalingDialerFunc func(context.Context, string, string) (net.Conn, error)

func (f signalingDialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

var _ Listener = (*NetherNetProxy)(nil)
