package proxy

import (
	"context"
	"net"

	"github.com/sandertv/go-raknet"
	"github.com/sandertv/gophertunnel/minecraft"
)

type rakNetPacketListener struct{}

func (rakNetPacketListener) ListenPacket(network, address string) (net.PacketConn, error) {
	return net.ListenPacket(listenNetworkForAddress(network, address), address)
}

func listenRakNet(address string) (*raknet.Listener, error) {
	return raknet.ListenConfig{UpstreamPacketListener: rakNetPacketListener{}}.Listen(address)
}

// rakNetListenNetwork lets the Minecraft listener use the same bind policy as
// the other RakNet modes without changing the registered network for dials.
type rakNetListenNetwork struct{ raknet.Dialer }

func (r rakNetListenNetwork) DialContext(ctx context.Context, address string) (net.Conn, error) {
	return r.Dialer.DialContext(ctx, address)
}

func (rakNetListenNetwork) Listen(address string) (minecraft.NetworkListener, error) {
	return listenRakNet(address)
}
