package proxy

import (
	"net"
	"testing"
)

// HY2 数据面在 QUIC 流上，可调优的只有 ConnFactory 建出的真实 UDP socket。
// 补全接口前 hysteria2PacketConn 不暴露 SetReadBuffer/SetWriteBuffer，
// trackedPacketConn 只能返回“不支持”并触发 WARN。
func TestHY2PacketConnExposesBufferTuning(t *testing.T) {
	factory := &hy2PortHoppingConnFactory{}
	conn := &hysteria2PacketConn{outbound: &SingboxOutbound{hy2ConnFactory: factory}}

	// 项目统一语义：一个大小、读写同时生效。调用方拿到的请求值应原样保留，
	// 由 configureUDPConnBuffers 在 socket 侧做归一化。
	if err := conn.SetReadBuffer(1 << 20); err != nil {
		t.Fatalf("SetReadBuffer 返回错误: %v", err)
	}
	if err := conn.SetWriteBuffer(1 << 20); err != nil {
		t.Fatalf("SetWriteBuffer 返回错误: %v", err)
	}
	if factory.pendingBuffers != 1<<20 {
		t.Fatalf("调优请求未保留: %d", factory.pendingBuffers)
	}
}

// socket 建好（含重连）时必须套用已记录的请求；双向都按同一大小设置。
func TestHY2ConnFactoryAppliesPendingBuffersOnNewSocket(t *testing.T) {
	factory := &hy2PortHoppingConnFactory{}
	factory.requestBufferSize(1 << 20)
	recorder := &bufferRecordingConn{countingPacketConn: &countingPacketConn{}}
	factory.adoptUDPSocket(recorder)

	recorder.mu.Lock()
	readSize, writeSize := recorder.read, recorder.write
	recorder.mu.Unlock()
	if readSize != 1<<20 || writeSize != 1<<20 {
		t.Fatalf("新建 socket 未套用调优: read=%d write=%d", readSize, writeSize)
	}

	// socket 已存在时，后续请求立即套用。
	factory.requestBufferSize(2 << 20)
	recorder.mu.Lock()
	readSize, writeSize = recorder.read, recorder.write
	recorder.mu.Unlock()
	if readSize != 2<<20 || writeSize != 2<<20 {
		t.Fatalf("存量 socket 未跟随新请求: read=%d write=%d", readSize, writeSize)
	}
}

// 链式模式没有本机 socket：请求保留、不报错，等真正建出 socket 再生效。
func TestHY2BufferRequestSurvivesWithoutLocalSocket(t *testing.T) {
	factory := &hy2PortHoppingConnFactory{}
	factory.requestBufferSize(1 << 20)
	if factory.pendingBuffers != 1<<20 {
		t.Fatalf("请求应保留等待 socket: %d", factory.pendingBuffers)
	}
}

// 补全接口后上层 trackedPacketConn 的调优不再降级为 WARN。
func TestTrackedPacketConnAcceptsHY2Tuning(t *testing.T) {
	conn := &hysteria2PacketConn{outbound: &SingboxOutbound{hy2ConnFactory: &hy2PortHoppingConnFactory{}}}
	tracked := &trackedPacketConn{PacketConn: conn}
	if err := tracked.SetReadBuffer(1 << 20); err != nil {
		t.Fatalf("上层仍会报不支持: %v", err)
	}
	if err := tracked.SetWriteBuffer(1 << 20); err != nil {
		t.Fatalf("上层仍会报不支持: %v", err)
	}
}

var _ net.PacketConn = (*trackedPacketConn)(nil)
