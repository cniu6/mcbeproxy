package proxy

import (
	"net"
	"reflect"
	"unsafe"

	utls "github.com/metacubex/utls"
	refutls "github.com/refraction-networking/utls"
	N "github.com/sagernet/sing/common/network"
	xrayreality "github.com/xtls/xray-core/transport/internet/reality"
)

//go:linkname vlessTLSRegistry github.com/sagernet/sing-vmess/vless.tlsRegistry
var vlessTLSRegistry []func(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer uintptr)

func init() {
	vlessTLSRegistry = append(vlessTLSRegistry, func(conn net.Conn) (loaded bool, netConn net.Conn, reflectType reflect.Type, reflectPointer uintptr) {
		realityConn, loaded := N.CastReader[*xrayreality.UConn](conn)
		if loaded {
			return true, realityConn.NetConn(), reflect.TypeOf(realityConn.UConn.Conn).Elem(), uintptr(unsafe.Pointer(realityConn.UConn.Conn))
		}
		refUConn, loaded := N.CastReader[*refutls.UConn](conn)
		if loaded {
			return true, refUConn.NetConn(), reflect.TypeOf(refUConn.Conn).Elem(), uintptr(unsafe.Pointer(refUConn.Conn))
		}
		refTLSConn, loaded := N.CastReader[*refutls.Conn](conn)
		if loaded {
			return true, refTLSConn.NetConn(), reflect.TypeOf(refTLSConn).Elem(), uintptr(unsafe.Pointer(refTLSConn))
		}
		uConn, loaded := N.CastReader[*utls.UConn](conn)
		if loaded {
			return true, uConn.NetConn(), reflect.TypeOf(uConn.Conn).Elem(), uintptr(unsafe.Pointer(uConn.Conn))
		}
		tlsConn, loaded := N.CastReader[*utls.Conn](conn)
		if loaded {
			return true, tlsConn.NetConn(), reflect.TypeOf(tlsConn).Elem(), uintptr(unsafe.Pointer(tlsConn))
		}
		return
	})
}
