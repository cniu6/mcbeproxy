package proxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

// 只使用本机 HTTP/UDP fixture；能力信息和身份来自目标，不在代理伪造版本或终止 DTLS。
func compatRelay(t *testing.T, handler http.Handler) *netherNetRelay {
	t.Helper()
	upstream := httptest.NewServer(handler)
	t.Cleanup(upstream.Close)
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	cfg := &config.ServerConfig{ID: "compat", Target: "127.0.0.1", Port: 1, NetherNetUpstream: upstream.URL}
	r, err := newNetherNetRelay(cfg.ID, func() *config.ServerConfig { return cfg }, nil, udp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	select {
	case <-r.firstProbe:
	case <-time.After(3 * time.Second):
		t.Fatal("initial probe did not finish")
	}
	return r
}

func TestNetherNetRelayCompatPreservesTargetMetadata(t *testing.T) {
	metadata := `{"name":"target","protocol":9999,"version":"target-defined","level":"world","players":2,"maxPlayers":10,"gameType":1,"extension":{"future":true}}`
	r := compatRelay(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.Header().Set("Content-Type", "application/json; charset=utf-8")
		w.WriteHeader(http.StatusAccepted)
		_, _ = io.WriteString(w, metadata)
	}))
	request := httptest.NewRequest(http.MethodGet, "http://127.0.0.1/v1/join", nil)
	response := httptest.NewRecorder()
	r.handleProbe(response, request)
	if response.Code != http.StatusAccepted {
		t.Errorf("status=%d, want upstream 202", response.Code)
	}
	if got := response.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("content type=%q", got)
	}
	if got := response.Body.String(); got != metadata {
		t.Errorf("target metadata changed or lost: %q", got)
	}
}

func TestNetherNetRelayCompatOpaqueIDAndSuccessAnswer(t *testing.T) {
	for _, id := range []string{"18446744073709551615", "e168a9f0-6c8b-4afc-905d-cf736e19fb3a"} {
		t.Run(id, func(t *testing.T) {
			media, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
			if err != nil {
				t.Fatal(err)
			}
			defer media.Close()
			offer := string(iceTestSDP("client", "client-password")) + "a=identity:client-identity-fixture\r\n"
			answer := string(iceTestSDP("compat", "unchanged-fixture")) + fmt.Sprintf("a=identity:target-identity-fixture\r\na=fingerprint:sha-256 AA:BB\r\na=candidate:1 1 udp 1 127.0.0.1 %d typ host\r\n", media.LocalAddr().(*net.UDPAddr).Port)
			seen := make(chan string, 1)
			r := compatRelay(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
				if req.Method == http.MethodGet {
					w.WriteHeader(http.StatusOK)
					return
				}
				body, _ := io.ReadAll(req.Body)
				if string(body) != offer {
					t.Errorf("offer modified: %q", body)
				}
				seen <- req.URL.Path
				w.Header().Set("Content-Type", "application/sdp")
				w.WriteHeader(http.StatusCreated)
				_, _ = io.WriteString(w, answer)
			}))
			request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1:21111/v1/join/"+id, strings.NewReader(offer))
			request.SetPathValue("networkID", id)
			response := httptest.NewRecorder()
			r.handleOffer(response, request)
			if response.Code < 200 || response.Code >= 300 {
				t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
			}
			select {
			case path := <-seen:
				if path != "/v1/join/"+id {
					t.Errorf("network ID changed: %q", path)
				}
			default:
				t.Fatal("offer did not reach target")
			}
			if r.count.Load() != 1 {
				t.Error("successful non-200 SDP answer was not bridged")
			}
			for _, line := range []string{"a=identity:target-identity-fixture", "a=fingerprint:sha-256 AA:BB", "a=ice-pwd:unchanged-fixture", "127.0.0.1 21111 typ host"} {
				if !strings.Contains(response.Body.String(), line) {
					t.Errorf("missing preserved/rewritten field %q", line)
				}
			}
		})
	}
}

func TestNetherNetRelayCompatColdProbeWaitsBriefly(t *testing.T) {
	metadata := `{"name":"ready-target","protocol":9999}`
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		time.Sleep(30 * time.Millisecond)
		w.Header().Set("Content-Type", "application/json")
		_, _ = io.WriteString(w, metadata)
	}))
	defer upstream.Close()
	udp, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer udp.Close()
	cfg := &config.ServerConfig{ID: "cold-probe", Target: "127.0.0.1", Port: 1, NetherNetUpstream: upstream.URL}
	r, err := newNetherNetRelay(cfg.ID, func() *config.ServerConfig { return cfg }, nil, udp)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	response := httptest.NewRecorder()
	start := time.Now()
	r.handleProbe(response, httptest.NewRequest(http.MethodGet, "http://127.0.0.1/v1/join", nil))
	if response.Code != http.StatusOK || response.Body.String() != metadata {
		t.Fatalf("ready target falsely reported unavailable: status=%d body=%q", response.Code, response.Body.String())
	}
	if time.Since(start) > 500*time.Millisecond {
		t.Error("capability probe exceeded bounded startup wait")
	}
}

// 两个同 IP 客户端各自持有 ICE 会话，代理只搬运 UDP 字节；此测试不声称是26.60实机登录。
func TestNetherNetRelayCompatSameIPMediaStaysOpaque(t *testing.T) {
	r := compatRelay(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	type peer struct {
		client *net.UDPConn
		target *net.UDPConn
		ufrag  string
	}
	peers := make([]peer, 2)
	for i := range peers {
		client, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = client.Close() })
		target, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = target.Close() })
		ufrag := fmt.Sprintf("peer%d", i)
		peers[i] = peer{client: client, target: target, ufrag: ufrag}
		answer := fmt.Sprintf("v=0\r\nm=application 9 UDP/DTLS/SCTP webrtc-datachannel\r\na=ice-ufrag:%s\r\na=identity:unchanged-%d\r\na=candidate:1 1 udp 1 127.0.0.1 %d typ host\r\n", ufrag, i, target.LocalAddr().(*net.UDPAddr).Port)
		req := httptest.NewRequest(http.MethodPost, "http://"+r.udp.LocalAddr().String()+"/v1/join/fixture", nil)
		if _, err := r.bridge(context.Background(), req, answer); err != nil {
			t.Fatal(err)
		}
		value, _ := r.sessions.Load(ufrag)
		value.(*netherNetSession).binding = netherNetICEBinding{clientUfrag: "client", serverUfrag: ufrag, serverPassword: "password"}
	}
	if r.count.Load() != 2 {
		t.Fatalf("sessions=%d, want 2", r.count.Load())
	}
	for round := 0; round < 2; round++ {
		for i, p := range peers {
			var payload []byte
			if round == 0 {
				payload = authenticatedSTUN(t, p.ufrag+":client", "password")
			} else {
				// 加密记录样式的任意二进制数据，不是能被代理解析的游戏包。
				payload = []byte{0x16, 0xfe, 0xfd, byte(i), 0x00, 0xff, 0x80, 0x00}
			}
			if !r.handleDatagram(payload, p.client.LocalAddr().(*net.UDPAddr).AddrPort()) {
				t.Fatal("session datagram not claimed")
			}
			buf := make([]byte, 2048)
			_ = p.target.SetReadDeadline(time.Now().Add(time.Second))
			n, from, err := p.target.ReadFromUDP(buf)
			if err != nil {
				t.Fatalf("target %d: %v", i, err)
			}
			if string(buf[:n]) != string(payload) {
				t.Fatalf("target %d bytes changed", i)
			}
			reply := append([]byte{byte(0x90 + i)}, buf[:n]...)
			if _, err := p.target.WriteToUDP(reply, from); err != nil {
				t.Fatal(err)
			}
			_ = p.client.SetReadDeadline(time.Now().Add(time.Second))
			n, from, err = p.client.ReadFromUDP(buf)
			if err != nil {
				t.Fatalf("client %d: %v", i, err)
			}
			if string(buf[:n]) != string(reply) {
				t.Fatalf("client %d received changed or crossed data", i)
			}
			if from.Port != int(r.listenPort) {
				t.Errorf("reply bypassed relay: %s", from)
			}
		}
	}
}

func TestNetherNetRelayCompatRejectsOversizedAnswer(t *testing.T) {
	r := compatRelay(t, http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.Method == http.MethodGet {
			w.WriteHeader(http.StatusOK)
			return
		}
		_, _ = io.WriteString(w, "v=0\n"+strings.Repeat("x", netherNetMaxSDPSize))
	}))
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	request := httptest.NewRequest(http.MethodPost, "http://127.0.0.1/v1/join/1", strings.NewReader("v=0\n")).WithContext(ctx)
	request.SetPathValue("networkID", "1")
	response := httptest.NewRecorder()
	r.handleOffer(response, request)
	if response.Code != http.StatusBadGateway {
		t.Errorf("oversized answer status=%d, want 502", response.Code)
	}
}
