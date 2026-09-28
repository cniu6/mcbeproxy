# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project Overview

MCPE Server Proxy - A high-performance UDP proxy for Minecraft Bedrock Edition game servers. Routes MCPE traffic through upstream proxy nodes (Shadowsocks, VMess, Hysteria2) with load balancing, player tracking, and access control.

## Build Commands

```bash
# Full build (frontend + Go binary for Windows/Linux)
build.bat

# Manual Go build (requires frontend built first)
go build -tags=with_utls -ldflags="-s -w" -o mcpeserverproxy.exe cmd/mcpeserverproxy/main.go

# Build frontend only
cd web && npm install && npm run build

# Run tests
go test ./...

# Run tests for specific package
go test ./internal/proxy/...
go test ./internal/config/...
```

## Running

```bash
# Default (uses config.json, server_list.json)
./mcpeserverproxy.exe

# Custom config
./mcpeserverproxy.exe -config myconfig.json -servers myservers.json

# Debug mode
./mcpeserverproxy.exe -debug
```

## Architecture

### Entry Point
`cmd/mcpeserverproxy/main.go` - Initializes all components: config loading, database, proxy server, ACL manager, API server.

### Core Packages (`internal/`)

| Package | Purpose |
|---------|---------|
| `proxy/` | Core proxy logic - listeners, forwarders, outbound management, load balancing |
| `config/` | Configuration management with hot reload (file watching) |
| `api/` | REST API (Gin) + embedded Vue.js dashboard |
| `session/` | Player session tracking with garbage collection |
| `db/` | SQLite persistence (players, sessions, ACL, API keys) |
| `acl/` | Blacklist/whitelist access control |
| `protocol/` | RakNet/MCBE protocol handling, login packet parsing |
| `auth/` | Xbox Live authentication |
| `monitor/` | Prometheus metrics, system stats, goroutine tracking |
| `logger/` | Structured logging with file rotation |

### Proxy Modes
- `passthrough` - Forwards raw RakNet bytes, extracts player info from login packets
- `raknet` - Full RakNet protocol proxy
- `mitm` - Man-in-the-middle with gophertunnel (full protocol access)
- `raw_udp` - Raw UDP forwarding
- `transparent` - Transparent proxy mode
- `nethernet` - Terminates NetherNet (WebRTC) on both sides via gophertunnel; sees player data, highest cost

### NetherNet relay (`nethernet_relay: true`)
Minecraft 26.x clients first probe NetherNet HTTP signaling on the TCP twin of the server port, then fall back to RakNet. With `nethernet_relay` on a `raw_udp` or plain `udp` server, `internal/proxy/nethernet_relay.go` answers that signaling, forwards the SDP offer upstream (through the outbound), rewrites only the answer's ICE candidates to the proxy's address, and relays the still-encrypted WebRTC media over the same UDP port as RakNet (demuxed by STUN ufrag). No decryption, no extra port; player names are not visible on that path. If the upstream has no NetherNet signaling, `GET /v1/join` returns 503 and clients use RakNet. Needs the TCP port opened alongside UDP.

### Hot path
Never block a shared receive loop: kick sends run via `sendKickAsync`, session DB writes via `sessionPersister`, and the transparent listener shards workers per client to keep packet order. `raw_udp`/`plain_udp` receive loops are allocation-free in steady state (`udpAddrCache`, `readPacketConn`/`writePacketConn` fast paths for dialed sockets). Guard with `go test ./internal/proxy -run '^$' -bench RoundTrip -benchmem` (0 allocs/op expected).

### Paced downstream (`downstream_limit_kbps`)
For servers behind a policed egress (cloud bandwidth cap) whose RakNet sender has no congestion control. `raknet` mode paces inside the vendored go-raknet (`SetSendRate`, see third_party/go-raknet/PATCHED.md). `raw_udp` uses `proxy/raw_udp_pacer.go`: the proxy ACKs/NACKs the server's datagrams itself, queues the frames byte for byte, sends them at the rate under its own datagram numbers, consumes the client's ACK/NACKs, and resends lost reliable frames under new numbers. While a pacer is active, `sendDatagramSeq` mirrors the pacer's numbering (injected kicks use `takeSeq`). A client silent for 10s is treated as gone: no more ACKs to the server, so the server times the player out.

### Network routing (`internal/netroute`, `network.json`)
Global outgoing interface + Proxifier-style destination rules (IP / CIDR / `a.b.c.*` / ranges / domains / `*.domain` / globs, per-target ports, port lists; actions default/direct/proxy/block, optional per-rule interface). Compiled once, published via an atomic pointer; with nothing configured every helper is the plain `net` call. Every outgoing socket must go through it: use `netroute.Dialer/BindDialer/DialContext/DialUDP/ListenUDP` instead of `net.Dialer{}` / `net.DialUDP` / `net.ListenUDP("udp", nil)`. sing-box nodes are covered by `directDialer`; xray and mihomo are hooked in `proxy/netroute_hooks.go`. Pinning uses `IP_UNICAST_IF` (Windows) / `SO_BINDTODEVICE` (Linux, source-address fallback); loopback is never pinned. Local interceptors that redirect to 127.0.0.1 (Proxifier, TUN) break pinned TCP. Rule actions apply to proxy-port traffic; the interface part applies to all outgoing sockets. API: `/api/network`, `/api/network/interfaces` (adaptive-TTL cache, `?refresh=1`), `/api/network/test`.

### Multi-user proxy ports (`users` in `proxy_ports.json`)
One listening port, many credentials, each with its own route (node / `@group` / `a,b` / `direct`, empty = port route), IP whitelist, max connections, expiry, UDP toggle and rule opt-out (`proxy/proxy_port_users.go`). The credential table is swapped atomically on edits (no listener restart, live connections keep their identity); per-user counters live in the manager's registry and survive restarts. SOCKS4 carries `user:pass` in USERID.

### Key Data Flow
1. Minecraft clients connect via RakNet UDP
2. Proxy extracts player info from login packets
3. Traffic routed through upstream proxy nodes (sing-box dialer factory)
4. Load balancer selects nodes (least-latency, round-robin, random, least-connections)
5. Sessions tracked in memory + persisted to SQLite

### Configuration Files
- `config.json` - Global settings (API port, database path, logging)
- `server_list.json` - MCPE server configurations (targets, ports, proxy modes)
- `proxy_outbounds.json` - Upstream proxy nodes (SS, VMess, Hysteria2)

### Frontend
`web/` - Vue 3 + Vite + Naive UI dashboard, built output goes to `internal/api/dist/` and is embedded in the Go binary.

### Key Dependencies
- `github.com/sandertv/gophertunnel` - MCBE protocol
- `github.com/sandertv/go-raknet` - RakNet UDP protocol
- `github.com/gin-gonic/gin` - HTTP API
- `github.com/apernet/hysteria` - Hysteria2 proxy
- `github.com/sagernet/sing-*` - sing-box proxy protocols
- `modernc.org/sqlite` - Pure Go SQLite
