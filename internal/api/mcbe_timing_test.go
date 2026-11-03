package api

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"os"
	"sync"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
	"mcpeserverproxy/internal/singboxcore"
)

// 内存回显保留 RakNet 时间戳，测试不访问真实节点，也不写节点配置。
type timingPacketConn struct {
	mu        sync.Mutex
	packet    []byte
	writes    int
	closed    bool
	failWarm  bool
	failFirst bool
}

func (c *timingPacketConn) WriteTo(p []byte, _ net.Addr) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.writes++
	c.packet = make([]byte, 35)
	c.packet[0] = 0x1c
	copy(c.packet[1:9], p[1:9])
	return len(p), nil
}
func (c *timingPacketConn) ReadFrom(p []byte) (int, net.Addr, error) {
	time.Sleep(3 * time.Millisecond)
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.failFirst && c.writes == 1 {
		return 0, nil, &net.OpError{Op: "read", Net: "udp", Err: os.ErrDeadlineExceeded}
	}
	if c.failWarm && c.writes > 1 {
		return 0, nil, errors.New("warm fixture failure")
	}
	return copy(p, c.packet), &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19132}, nil
}
func (c *timingPacketConn) Close() error {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.closed = true
	return nil
}
func (c *timingPacketConn) LocalAddr() net.Addr              { return &net.UDPAddr{} }
func (c *timingPacketConn) SetDeadline(time.Time) error      { return nil }
func (c *timingPacketConn) SetReadDeadline(time.Time) error  { return nil }
func (c *timingPacketConn) SetWriteDeadline(time.Time) error { return nil }

type timingOutbound struct {
	pc     *timingPacketConn
	closed bool
}

func (o *timingOutbound) ListenPacket(context.Context, string) (net.PacketConn, error) {
	time.Sleep(3 * time.Millisecond)
	return o.pc, nil
}
func (o *timingOutbound) Close() error { o.closed = true; return nil }

func TestMCBETimingVLESSWarmAndJSON(t *testing.T) {
	for _, failWarm := range []bool{false, true} {
		t.Run(map[bool]string{false: "warm", true: "warm_failure_keeps_first"}[failWarm], func(t *testing.T) {
			pc := &timingPacketConn{failWarm: failWarm}
			outbound := &timingOutbound{pc: pc}
			h := &ProxyOutboundHandler{singboxFactory: singboxcore.FactoryFuncs{CreateUDPOutboundFunc: func(context.Context, *config.ProxyOutbound) (singboxcore.UDPOutbound, error) { return outbound, nil }}}
			result := h.testMCBEServer(context.Background(), &config.ProxyOutbound{Name: "fixture", Type: config.ProtocolVLESS}, "127.0.0.1:19132")
			if !result.Success {
				t.Fatalf("ping failed: %s", result.Error)
			}
			if pc.writes != 2 {
				t.Errorf("VLESS ping count=%d, want same-connection first+warm", pc.writes)
			}
			if !pc.closed || !outbound.closed {
				t.Error("test connection or outbound leaked")
			}
			data, err := json.Marshal(result)
			if err != nil {
				t.Fatal(err)
			}
			var fields map[string]any
			if err = json.Unmarshal(data, &fields); err != nil {
				t.Fatal(err)
			}
			for _, key := range []string{"open_ms", "ping_ms", "total_ms", "first_latency_ms", "from_cache", "warm"} {
				if _, ok := fields[key]; !ok {
					t.Errorf("response missing %s", key)
				}
			}
			if open, ok := fields["open_ms"].(float64); ok && open <= 0 {
				t.Error("open time was not measured")
			}
			if warm, ok := fields["warm"].(bool); ok && warm == failWarm {
				t.Errorf("warm flag=%v, warm failure=%v", warm, failWarm)
			}
			if total, ok := fields["total_ms"].(float64); ok {
				if total < fields["open_ms"].(float64)+fields["ping_ms"].(float64) {
					t.Error("total excludes part of test")
				}
			}
		})
	}
}

func TestMCBETimingRetryUsesWarmBeforeCleanup(t *testing.T) {
	first := &timingOutbound{pc: &timingPacketConn{failFirst: true}}
	second := &timingOutbound{pc: &timingPacketConn{}}
	calls := 0
	h := &ProxyOutboundHandler{singboxFactory: singboxcore.FactoryFuncs{CreateUDPOutboundFunc: func(context.Context, *config.ProxyOutbound) (singboxcore.UDPOutbound, error) {
		calls++
		if calls == 1 {
			return first, nil
		}
		return second, nil
	}}}
	result := h.testMCBEServer(context.Background(), &config.ProxyOutbound{Name: "fixture", Type: config.ProtocolVLESS}, "127.0.0.1:19132")
	if !result.Success || !result.Warm {
		t.Fatalf("retry did not return a warm success: %+v", result)
	}
	if calls != 2 || first.pc.writes != 1 || second.pc.writes != 2 {
		t.Fatalf("unexpected attempts: calls=%d first=%d second=%d", calls, first.pc.writes, second.pc.writes)
	}
	if !first.closed || !second.closed || !first.pc.closed || !second.pc.closed {
		t.Error("retry leaked test resources")
	}
	if result.OpenMs <= 0 || result.PingMs <= 0 || result.TotalMs < result.OpenMs+result.PingMs {
		t.Fatalf("invalid retry timing: %+v", result)
	}
}

func TestMCBETimingOpenFailure(t *testing.T) {
	h := &ProxyOutboundHandler{singboxFactory: singboxcore.FactoryFuncs{CreateUDPOutboundFunc: func(context.Context, *config.ProxyOutbound) (singboxcore.UDPOutbound, error) {
		time.Sleep(3 * time.Millisecond)
		return nil, errors.New("fixture open failure")
	}}}
	result := h.testMCBEServer(context.Background(), &config.ProxyOutbound{Name: "fixture", Type: config.ProtocolVLESS}, "127.0.0.1:19132")
	if result.Success {
		t.Fatal("expected failure")
	}
	data, _ := json.Marshal(result)
	var fields map[string]any
	_ = json.Unmarshal(data, &fields)
	for _, key := range []string{"open_ms", "total_ms"} {
		if value, ok := fields[key].(float64); !ok || value <= 0 {
			t.Errorf("missing failed-open timing %s: %s", key, data)
		}
	}
}
