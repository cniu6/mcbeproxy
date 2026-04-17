package singboxcore

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"

	"github.com/sagernet/sing-vmess/vless"
	"github.com/sagernet/sing/common/buf"
	slog "github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
)

type vlessUDPPacketEvent struct {
	payload     []byte
	destination string
}

type vlessUDPEchoHandler struct {
	packets chan vlessUDPPacketEvent
	errs    chan error
}

func newVLESSUDPEchoHandler() *vlessUDPEchoHandler {
	return &vlessUDPEchoHandler{
		packets: make(chan vlessUDPPacketEvent, 1),
		errs:    make(chan error, 4),
	}
}

func (h *vlessUDPEchoHandler) pushErr(err error) {
	if err == nil {
		return
	}
	select {
	case h.errs <- err:
	default:
	}
}

func (h *vlessUDPEchoHandler) NewConnectionEx(_ context.Context, conn net.Conn, _ M.Socksaddr, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	_ = conn.Close()
	err := errors.New("unexpected tcp connection in vless udp poc test")
	if onClose != nil {
		onClose(err)
	}
	h.pushErr(err)
}

func (h *vlessUDPEchoHandler) NewPacketConnectionEx(_ context.Context, conn N.PacketConn, _ M.Socksaddr, _ M.Socksaddr, onClose N.CloseHandlerFunc) {
	defer func() {
		_ = conn.Close()
		if onClose != nil {
			onClose(nil)
		}
	}()
	buffer := buf.NewPacket()
	defer buffer.Release()
	destination, err := conn.ReadPacket(buffer)
	if err != nil {
		h.pushErr(err)
		return
	}
	payload := append([]byte(nil), buffer.Bytes()...)
	select {
	case h.packets <- vlessUDPPacketEvent{payload: payload, destination: destination.String()}:
	default:
	}
	const headerReserve = 64
	const tailReserve = 64
	reply := buf.NewSize(headerReserve + len(payload) + tailReserve)
	reply.Resize(headerReserve, 0)
	if _, err := reply.Write(payload); err != nil {
		reply.Release()
		h.pushErr(err)
		return
	}
	if err := conn.WritePacket(reply, destination); err != nil {
		reply.Release()
		h.pushErr(err)
	}
}

func newVLESSUDPPipeDialer(uuid string, handler *vlessUDPEchoHandler) DialContextFunc {
	service := vless.NewService[string](slog.NOP(), handler)
	service.UpdateUsers([]string{"test-user"}, []string{uuid}, []string{""})
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if network != "tcp" {
			return nil, fmt.Errorf("unexpected network %s", network)
		}
		if address == "" {
			return nil, fmt.Errorf("unexpected empty address")
		}
		clientConn, serverConn := net.Pipe()
		go func() {
			defer serverConn.Close()
			err := service.NewConnection(ctx, serverConn, M.Socksaddr{}, nil)
			if isIgnorableVLESSPipeError(err) {
				return
			}
			handler.pushErr(err)
		}()
		return clientConn, nil
	}
}

func isIgnorableVLESSPipeError(err error) bool {
	if err == nil || errors.Is(err, io.EOF) || errors.Is(err, net.ErrClosed) || errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	text := strings.ToLower(err.Error())
	return strings.Contains(text, "closed pipe") || strings.Contains(text, "use of closed network connection")
}

func testVLESSUDPCfg(uuid string) *config.ProxyOutbound {
	return &config.ProxyOutbound{
		Name:    "vless-udp-poc",
		Type:    config.ProtocolVLESS,
		Server:  "127.0.0.1",
		Port:    443,
		UUID:    uuid,
		Enabled: true,
	}
}

func TestVLESSUDPPoCFactoryRoundTrip(t *testing.T) {
	const uuid = "11111111-1111-1111-1111-111111111111"
	handler := newVLESSUDPEchoHandler()
	factory := NewVLESSUDPPoCFactory(VLESSUDPPoCOptions{DialContext: newVLESSUDPPipeDialer(uuid, handler)})
	outbound, err := factory.CreateUDPOutbound(context.Background(), testVLESSUDPCfg(uuid))
	if err != nil {
		t.Fatalf("CreateUDPOutbound returned error: %v", err)
	}
	conn, err := outbound.ListenPacket(context.Background(), "1.2.3.4:19132")
	if err != nil {
		t.Fatalf("ListenPacket returned error: %v", err)
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))

	payload := []byte("ping")
	_, err = conn.WriteTo(payload, &net.UDPAddr{IP: net.IPv4(5, 6, 7, 8), Port: 9999})
	if err != nil {
		t.Fatalf("WriteTo returned error: %v", err)
	}

	select {
	case packet := <-handler.packets:
		if string(packet.payload) != string(payload) {
			t.Fatalf("unexpected server payload %q", string(packet.payload))
		}
		if packet.destination != "1.2.3.4:19132" {
			t.Fatalf("expected baked destination 1.2.3.4:19132, got %q", packet.destination)
		}
	case err := <-handler.errs:
		t.Fatalf("server handler returned error: %v", err)
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for server packet")
	}

	buffer := make([]byte, 32)
	n, addr, err := conn.ReadFrom(buffer)
	if err != nil {
		t.Fatalf("ReadFrom returned error: %v", err)
	}
	if got := string(buffer[:n]); got != string(payload) {
		t.Fatalf("unexpected echoed payload %q", got)
	}
	if addr == nil || addr.String() != "1.2.3.4:19132" {
		t.Fatalf("unexpected echoed address %v", addr)
	}
}

func TestVLESSUDPPoCRejectsUnsupportedTransport(t *testing.T) {
	cfg := testVLESSUDPCfg("11111111-1111-1111-1111-111111111111")
	cfg.Network = "grpc"
	_, err := NewVLESSUDPOutbound(cfg, VLESSUDPPoCOptions{})
	if err == nil {
		t.Fatal("expected unsupported transport error, got nil")
	}
}
