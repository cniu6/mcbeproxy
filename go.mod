module mcpeserverproxy

// 使用本机已安装的 Go 1.24.5 版本；如需升级 Go，请同步更新此处
go 1.26.0

require (
	github.com/anytls/sing-anytls v0.0.13
	github.com/apernet/hysteria/core/v2 v2.12.3
	github.com/apernet/hysteria/extras/v2 v2.12.3
	github.com/df-mc/go-nethernet v1.0.20
	github.com/fsnotify/fsnotify v1.9.0
	github.com/gin-gonic/gin v1.11.0
	github.com/golang-jwt/jwt/v4 v4.5.2
	github.com/golang/snappy v1.0.0
	github.com/google/pprof v0.0.0-20251213031049-b05bdaca462f
	github.com/google/uuid v1.6.0
	github.com/klauspost/compress v1.18.2
	github.com/leanovate/gopter v0.2.9
	github.com/metacubex/mihomo v1.19.31
	github.com/metacubex/utls v1.8.7
	github.com/pion/webrtc/v4 v4.2.16-0.20260627075746-7a223a6f4d4f
	github.com/prometheus/client_golang v1.23.2
	github.com/refraction-networking/utls v1.8.3-0.20260301010127-aa6edf4b11af
	github.com/sagernet/sing v0.9.5
	github.com/sagernet/sing-shadowsocks v0.2.9
	github.com/sagernet/sing-vmess v0.2.8
	github.com/sandertv/go-raknet v1.15.2-0.20260705184311-0d1fd09e2cf6
	github.com/sandertv/gophertunnel v1.61.0
	github.com/shirou/gopsutil/v3 v3.24.5
	github.com/xtls/xray-core v1.260327.0
	golang.org/x/crypto v0.54.0
	golang.org/x/net v0.57.0
	golang.org/x/oauth2 v0.36.0
	golang.org/x/sync v0.22.0
	google.golang.org/grpc v1.79.3
	gopkg.in/yaml.v3 v3.0.1
	modernc.org/sqlite v1.40.1
)

require (
	github.com/RyuaNerin/go-krypto v1.3.0 // indirect
	github.com/Yawning/aez v0.0.0-20211027044916-e49e68abd344 // indirect
	github.com/akutz/memconn v0.1.0 // indirect
	github.com/andybalholm/brotli v1.1.1 // indirect
	github.com/apernet/quic-go v0.62.1-0.20260912175848-73339f7edbb9 // indirect
	github.com/bahlo/generic-list-go v0.2.0 // indirect
	github.com/beorn7/perks v1.0.1 // indirect
	github.com/bytedance/sonic v1.14.0 // indirect
	github.com/bytedance/sonic/loader v0.3.0 // indirect
	github.com/cespare/xxhash/v2 v2.3.0 // indirect
	github.com/cloudflare/circl v1.6.3 // indirect
	github.com/cloudwego/base64x v0.1.6 // indirect
	github.com/coder/websocket v1.8.14 // indirect
	github.com/coreos/go-iptables v0.8.0 // indirect
	github.com/coreos/go-oidc/v3 v3.17.0 // indirect
	github.com/davecgh/go-spew v1.1.2-0.20180830191138-d8f796af33cc // indirect
	github.com/df-mc/go-playfab/v2 v2.0.2 // indirect
	github.com/df-mc/go-xsapi/v2 v2.0.3 // indirect
	github.com/df-mc/jsonc v1.0.5 // indirect
	github.com/dunglas/httpsfv v1.0.2 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/easytier/easytier/easytier-go v0.0.0-20260910071355-3d0c9c3ca5e2 // indirect
	github.com/enfein/mieru/v3 v3.37.0 // indirect
	github.com/ericlagergren/aegis v0.0.0-20250325060835-cd0defd64358 // indirect
	github.com/ericlagergren/polyval v0.0.0-20220411101811-e25bc10ba391 // indirect
	github.com/ericlagergren/siv v0.0.0-20220507050439-0b757b3aa5f1 // indirect
	github.com/ericlagergren/subtle v0.0.0-20220507045147-890d697da010 // indirect
	github.com/fxamacker/cbor/v2 v2.9.0 // indirect
	github.com/gabriel-vasile/mimetype v1.4.8 // indirect
	github.com/gaukas/godicttls v0.0.4 // indirect
	github.com/gin-contrib/sse v1.1.0 // indirect
	github.com/go-gl/mathgl v1.2.0 // indirect
	github.com/go-jose/go-jose/v4 v4.1.4 // indirect
	github.com/go-ole/go-ole v1.3.0 // indirect
	github.com/go-playground/locales v0.14.1 // indirect
	github.com/go-playground/universal-translator v0.18.1 // indirect
	github.com/go-playground/validator/v10 v10.27.0 // indirect
	github.com/gobwas/httphead v0.1.0 // indirect
	github.com/gobwas/pool v0.2.1 // indirect
	github.com/gobwas/ws v1.4.0 // indirect
	github.com/goccy/go-json v0.10.2 // indirect
	github.com/goccy/go-yaml v1.18.0 // indirect
	github.com/gofrs/uuid/v5 v5.4.0 // indirect
	github.com/golang/groupcache v0.0.0-20241129210726-2c02b8208cf8 // indirect
	github.com/google/btree v1.1.3 // indirect
	github.com/google/go-cmp v0.7.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/insomniacslk/dhcp v0.0.0-20250109001534-8abf58130905 // indirect
	github.com/josharian/native v1.1.0 // indirect
	github.com/jsimonetti/rtnetlink v1.4.0 // indirect
	github.com/json-iterator/go v1.1.12 // indirect
	github.com/juju/ratelimit v1.0.2 // indirect
	github.com/klauspost/cpuid/v2 v2.3.0 // indirect
	github.com/klauspost/reedsolomon v1.12.3 // indirect
	github.com/leodido/go-urn v1.4.0 // indirect
	github.com/lufia/plan9stats v0.0.0-20211012122336-39d0f177ccd0 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/mdlayher/netlink v1.7.2 // indirect
	github.com/mdlayher/socket v0.5.1 // indirect
	github.com/metacubex/amneziawg-go v0.0.0-20260908071407-0c1c6f40ecd7 // indirect
	github.com/metacubex/ascon v0.1.0 // indirect
	github.com/metacubex/bart v0.29.0 // indirect
	github.com/metacubex/bbolt v0.0.0-20260706163408-d4ec34ad7c48 // indirect
	github.com/metacubex/blake3 v0.1.0 // indirect
	github.com/metacubex/chacha v0.1.5 // indirect
	github.com/metacubex/connect-ip-go v0.0.0-20260727083417-67ccdb0cf771 // indirect
	github.com/metacubex/cpu v0.1.1 // indirect
	github.com/metacubex/edwards25519 v1.2.0 // indirect
	github.com/metacubex/fswatch v0.1.1 // indirect
	github.com/metacubex/gopacket v1.1.20-0.20230608035415-7e2f98a3e759 // indirect
	github.com/metacubex/gvisor v0.0.0-20260826100401-79317d808312 // indirect
	github.com/metacubex/hkdf v0.1.0 // indirect
	github.com/metacubex/hpke v0.1.0 // indirect
	github.com/metacubex/http v0.1.7 // indirect
	github.com/metacubex/jls-quic-go v0.0.0-20260727080412-732f2fc9a34d // indirect
	github.com/metacubex/jls-tls v0.0.0-20260723084315-67adc0e2f796 // indirect
	github.com/metacubex/jsonv2 v0.0.0-20260721082349-16b4998c8f89 // indirect
	github.com/metacubex/kcp-go v0.0.0-20260105040817-550693377604 // indirect
	github.com/metacubex/mipstack v0.0.0-20260910230046-ba762df4c91d // indirect
	github.com/metacubex/mlkem v0.1.0 // indirect
	github.com/metacubex/qpack v0.6.0 // indirect
	github.com/metacubex/quic-go v0.61.1-0.20260727080200-2548683b76f4 // indirect
	github.com/metacubex/randv2 v0.2.0 // indirect
	github.com/metacubex/restls-client-go v0.1.9 // indirect
	github.com/metacubex/sing v0.5.7 // indirect
	github.com/metacubex/sing-mux v0.3.10 // indirect
	github.com/metacubex/sing-quic v0.0.0-20260904234848-1c242664697a // indirect
	github.com/metacubex/sing-shadowsocks v0.2.13 // indirect
	github.com/metacubex/sing-shadowsocks2 v0.2.8 // indirect
	github.com/metacubex/sing-vmess v0.2.5 // indirect
	github.com/metacubex/sing-wireguard v0.0.0-20260826105301-c3ae17d19f9e // indirect
	github.com/metacubex/smux v0.0.0-20260105030934-d0c8756d3141 // indirect
	github.com/metacubex/ssh v0.1.0 // indirect
	github.com/metacubex/tailscale v0.0.0-20260821153257-ff0ecd818181 // indirect
	github.com/metacubex/tailscale-wireguard-go v0.0.0-20260725073821-e61ab99cede2 // indirect
	github.com/metacubex/tfo-go v0.0.0-20260623020846-376a77860b8c // indirect
	github.com/metacubex/tls v0.1.8 // indirect
	github.com/metacubex/wazero v0.0.0-20260628025728-9ae6bdcf2a7d // indirect
	github.com/metacubex/wireguard-go v0.0.0-20250820062549-a6cecdd7f57f // indirect
	github.com/metacubex/yamux v0.0.0-20250918083631-dd5f17c0be49 // indirect
	github.com/metacubex/zerotier-go v0.0.0-20260813124750-13fa6f45da5f // indirect
	github.com/miekg/dns v1.1.72 // indirect
	github.com/mitchellh/go-ps v1.0.0 // indirect
	github.com/modern-go/concurrent v0.0.0-20180306012644-bacd9c7ef1dd // indirect
	github.com/modern-go/reflect2 v1.0.2 // indirect
	github.com/mroth/weightedrand/v2 v2.1.0 // indirect
	github.com/munnerz/goautoneg v0.0.0-20191010083416-a7dc8b61c822 // indirect
	github.com/ncruces/go-strftime v0.1.9 // indirect
	github.com/oasisprotocol/deoxysii v0.0.0-20220228165953-2091330c22b7 // indirect
	github.com/openacid/low v0.1.21 // indirect
	github.com/pelletier/go-toml/v2 v2.2.4 // indirect
	github.com/pierrec/lz4/v4 v4.1.27 // indirect
	github.com/pion/datachannel v1.6.2 // indirect
	github.com/pion/dtls/v3 v3.1.4 // indirect
	github.com/pion/ice/v4 v4.2.7 // indirect
	github.com/pion/interceptor v0.1.45 // indirect
	github.com/pion/logging v0.2.4 // indirect
	github.com/pion/mdns/v2 v2.1.0 // indirect
	github.com/pion/randutil v0.1.0 // indirect
	github.com/pion/rtcp v1.2.16 // indirect
	github.com/pion/rtp v1.10.2 // indirect
	github.com/pion/sctp v1.10.2 // indirect
	github.com/pion/sdp/v3 v3.0.19 // indirect
	github.com/pion/srtp/v3 v3.0.12 // indirect
	github.com/pion/stun/v3 v3.1.6 // indirect
	github.com/pion/transport/v4 v4.0.2 // indirect
	github.com/pion/turn/v5 v5.0.10 // indirect
	github.com/pires/go-proxyproto v0.11.0 // indirect
	github.com/power-devops/perfstat v0.0.0-20210106213030-5aafc221ea8c // indirect
	github.com/prometheus/client_model v0.6.2 // indirect
	github.com/prometheus/common v0.66.1 // indirect
	github.com/prometheus/procfs v0.16.1 // indirect
	github.com/quic-go/qpack v0.6.0 // indirect
	github.com/quic-go/quic-go v0.60.0 // indirect
	github.com/rasky/go-lzo v0.0.0-20200203143853-96a758eda86e // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/safchain/ethtool v0.3.0 // indirect
	github.com/samber/lo v1.53.0 // indirect
	github.com/shoenig/go-m1cpu v0.1.6 // indirect
	github.com/sina-ghaderi/poly1305 v0.0.0-20220724002748-c5926b03988b // indirect
	github.com/sina-ghaderi/rabaead v0.0.0-20220730151906-ab6e06b96e8c // indirect
	github.com/sina-ghaderi/rabbitio v0.0.0-20220730151941-9ce26f4f872e // indirect
	github.com/sirupsen/logrus v1.9.4 // indirect
	github.com/stretchr/objx v0.5.3 // indirect
	github.com/stretchr/testify v1.12.1 // indirect
	github.com/tailscale/certstore v0.1.1-0.20260409135935-3638fb84b77d // indirect
	github.com/tailscale/go-winio v0.0.0-20231025203758-c4f33415bf55 // indirect
	github.com/tailscale/hujson v0.0.0-20221223112325-20486734a56a // indirect
	github.com/tailscale/peercred v0.0.0-20250107143737-35a0c7bd7edc // indirect
	github.com/tklauser/go-sysconf v0.3.12 // indirect
	github.com/tklauser/numcpus v0.6.1 // indirect
	github.com/twitchyliquid64/golang-asm v0.15.1 // indirect
	github.com/u-root/uio v0.0.0-20230220225925-ffce2a382923 // indirect
	github.com/ugorji/go/codec v1.3.0 // indirect
	github.com/vmihailenco/msgpack/v5 v5.4.1 // indirect
	github.com/vmihailenco/tagparser/v2 v2.0.0 // indirect
	github.com/wlynxg/anet v0.0.5 // indirect
	github.com/x448/float16 v0.8.4 // indirect
	github.com/xtls/reality v0.0.0-20260322125925-9234c772ba8f // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	github.com/yusufpapurcu/wmi v1.2.4 // indirect
	gitlab.com/go-extension/aes-ccm v0.0.0-20230221065045-e58665ef23c7 // indirect
	gitlab.com/yawning/bsaes.git v0.0.0-20190805113838-0a714cd429ec // indirect
	go.yaml.in/yaml/v2 v2.4.2 // indirect
	go.yaml.in/yaml/v3 v3.0.5 // indirect
	go4.org/mem v0.0.0-20240501181205-ae6ca9944745 // indirect
	go4.org/netipx v0.0.0-20231129151722-fdeea329fbba // indirect
	golang.org/x/arch v0.20.0 // indirect
	golang.org/x/exp v0.0.0-20250620022241-b7579e27df2b // indirect
	golang.org/x/mod v0.37.0 // indirect
	golang.org/x/sys v0.47.0 // indirect
	golang.org/x/term v0.45.0 // indirect
	golang.org/x/text v0.40.0 // indirect
	golang.org/x/time v0.15.0 // indirect
	golang.org/x/tools v0.47.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/protobuf v1.36.11 // indirect
	lukechampine.com/blake3 v1.4.1 // indirect
	modernc.org/libc v1.66.10 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

replace github.com/xtls/xray-core => ./third_party/xray-core
