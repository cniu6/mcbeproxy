package proxy

import (
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"sync"
	"testing"
	"time"
)

// 可控读泵只提供完整报文，不经过操作系统UDP队列，区分网络丢包与本层主动丢弃。
type chainBurstConn struct {
	count, size, next int
	exhausted         chan struct{}
	done              chan struct{}
	once              sync.Once
}

func (c *chainBurstConn) ReadFrom(b []byte) (int, net.Addr, error) {
	if c.next >= c.count {
		if c.next == c.count {
			close(c.exhausted)
			c.next++
		}
		<-c.done
		return 0, nil, net.ErrClosed
	}
	for i := 0; i < c.size; i++ {
		b[i] = byte(c.next)
	}
	binary.LittleEndian.PutUint32(b, uint32(c.next))
	c.next++
	return c.size, &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 19132}, nil
}
func (c *chainBurstConn) WriteTo(b []byte, _ net.Addr) (int, error) { return len(b), nil }
func (c *chainBurstConn) Close() error                              { c.once.Do(func() { close(c.done) }); return nil }
func (c *chainBurstConn) LocalAddr() net.Addr                       { return &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)} }
func (c *chainBurstConn) SetDeadline(time.Time) error               { return nil }
func (c *chainBurstConn) SetReadDeadline(time.Time) error           { return nil }
func (c *chainBurstConn) SetWriteDeadline(time.Time) error          { return nil }

func newChainBurstFixture(t *testing.T, count, size int) *chainTransportPacket {
	t.Helper()
	raw := &chainBurstConn{count: count, size: size, exhausted: make(chan struct{}), done: make(chan struct{})}
	conn := newChainTransportPacket(raw)
	t.Cleanup(func() {
		_ = conn.Close()
		select {
		case <-conn.terminal:
		case <-time.After(time.Second):
			t.Error("读泵未随关闭退出")
		}
	})
	select {
	case <-raw.exhausted:
	case <-time.After(time.Second):
		t.Fatal("突发消费阻塞了底层读泵")
	}
	return conn
}

func TestChainTransportBurstEvidence(t *testing.T) {
	conn := newChainBurstFixture(t, 64, 1400)
	_ = conn.SetReadDeadline(time.Now().Add(time.Second))
	buf := make([]byte, 2048)
	for i := 0; i < 64; i++ {
		n, addr, err := conn.ReadFrom(buf)
		if err != nil {
			t.Fatalf("下层交付64个完整报文，读取%d个后失败: %v", i, err)
		}
		if n != 1400 || binary.LittleEndian.Uint32(buf) != uint32(i) || buf[n-1] != byte(i) || addr.String() != "127.0.0.1:19132" {
			t.Fatalf("报文顺序、边界或内容损坏: index=%d n=%d addr=%v", i, n, addr)
		}
	}
}

// 使用JSON契约，缺少观测能力时以行为断言失败，而非缺字段的编译错误。
func chainBufferSnapshot(t *testing.T, conn net.PacketConn) map[string]any {
	t.Helper()
	raw, err := json.Marshal(packetConnectionDiagnostics(conn))
	if err != nil {
		t.Fatal(err)
	}
	var records []map[string]any
	if err = json.Unmarshal(raw, &records); err != nil {
		t.Fatal(err)
	}
	for _, record := range records {
		if record["layer"] == "chain_udp_buffer" {
			if buffer, ok := record["packet_buffer"].(map[string]any); ok {
				return buffer
			}
		}
	}
	t.Fatalf("断线诊断缺少链内缓冲计数: %s", raw)
	return nil
}

func TestChainTransportBurstBoundsAndCounters(t *testing.T) {
	for _, tc := range []struct {
		name              string
		count, size, kept int
	}{
		{"packet-bound", 300, 1400, 256},
		{"byte-bound", 64, 65535, 16},
	} {
		t.Run(tc.name, func(t *testing.T) {
			conn := newChainBurstFixture(t, tc.count, tc.size)
			snapshot := chainBufferSnapshot(t, conn)
			for field, want := range map[string]int{
				"queue_packets": tc.kept, "queue_bytes": tc.kept * tc.size,
				"packet_limit": 256, "byte_limit": 1 << 20,
				"received_packets": tc.count, "received_bytes": tc.count * tc.size,
				"dropped_packets": tc.count - tc.kept, "dropped_bytes": (tc.count - tc.kept) * tc.size,
				"peak_packets": tc.kept, "peak_bytes": tc.kept * tc.size,
			} {
				if got := snapshot[field]; got != float64(want) {
					t.Fatalf("%s=%v want=%d", field, got, want)
				}
			}
			if _, ok := snapshot["last_drop_at"]; !ok {
				t.Fatal("缺少最近溢出时间")
			}
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			buf := make([]byte, tc.size)
			for i := 0; i < tc.kept; i++ {
				if _, _, err := conn.ReadFrom(buf); err != nil {
					t.Fatal(err)
				}
				if binary.LittleEndian.Uint32(buf) != uint32(i) {
					t.Fatal("队列覆盖了已接收报文")
				}
			}
			after := chainBufferSnapshot(t, conn)
			if after["queue_packets"] != float64(0) || after["queue_bytes"] != float64(0) {
				t.Fatalf("消费后未释放预算: %+v", after)
			}
			if snapshot["queue_bytes"] != float64(tc.kept*tc.size) {
				t.Fatal("后续活动污染已返回快照")
			}
		})
	}
}

func TestChainTransportBurstCloseAndDeadline(t *testing.T) {
	conn := newChainBurstFixture(t, 256, 1400)
	_ = conn.SetReadDeadline(time.Now().Add(-time.Second))
	if _, _, err := conn.ReadFrom(make([]byte, 2048)); !errors.Is(err, os.ErrDeadlineExceeded) {
		t.Fatalf("有排队数据时也须尊重到期: %v", err)
	}
	_ = conn.SetReadDeadline(time.Time{})
	if _, _, err := conn.ReadFrom(make([]byte, 1)); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("短缓冲应明确失败: %v", err)
	}
	if got := chainBufferSnapshot(t, conn)["queue_packets"]; got != float64(255) {
		t.Fatalf("短读取未归还预算: %v", got)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := conn.ReadFrom(make([]byte, 2048)); !errors.Is(err, net.ErrClosed) {
		t.Fatalf("关闭后不能继续交付旧队列: %v", err)
	}
	snapshot := chainBufferSnapshot(t, conn)
	if snapshot["queue_packets"] != float64(0) || snapshot["queue_bytes"] != float64(0) {
		t.Fatalf("关闭后队列仍占内存: %+v", snapshot)
	}
}
