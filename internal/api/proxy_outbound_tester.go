package api

import (
	"context"
	"fmt"
	"time"

	"mcpeserverproxy/internal/proxy"
)

const defaultMCBEUDPTestAddress = "mco.cubecraft.net:19132"

// TestTCP implements scheduler.ProxyOutboundTester.
func (h *ProxyOutboundHandler) TestTCP(name string) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}
	if h.outboundMgr == nil {
		return fmt.Errorf("outbound manager not initialized")
	}
	if _, ok := h.configMgr.GetOutbound(name); !ok {
		return fmt.Errorf("proxy outbound not found: %s", name)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	startTime := time.Now()
	err := h.outboundMgr.CheckHealth(ctx, name)
	latency := time.Since(startTime).Milliseconds()

	if outbound, ok := h.configMgr.GetOutbound(name); ok {
		if err == nil {
			outbound.TCPLatencyMs = latency
		} else {
			outbound.TCPLatencyMs = 0
		}
		_ = h.configMgr.UpdateOutbound(name, outbound)
	}

	return err
}

// TestHTTP implements scheduler.ProxyOutboundTester.
func (h *ProxyOutboundHandler) TestHTTP(name string) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}

	cfg, ok := h.configMgr.GetOutbound(name)
	if !ok {
		return fmt.Errorf("proxy outbound not found: %s", name)
	}

	dialer, err := proxy.CreateSingboxDialer(cfg)
	if err != nil {
		return fmt.Errorf("failed to create proxy dialer: %w", err)
	}
	defer dialer.Close()

	target := DefaultHTTPTestTargets[0]
	httpResult := h.testHTTPThroughProxy(dialer, target)

	if outbound, ok := h.configMgr.GetOutbound(name); ok {
		if httpResult.Success {
			outbound.SetHTTPLatencyMs(httpResult.LatencyMs)
		} else {
			outbound.SetHTTPLatencyMs(0)
		}
		_ = h.configMgr.UpdateOutbound(name, outbound)
	}

	if httpResult.Success {
		return nil
	}
	if httpResult.Error != "" {
		return fmt.Errorf("%s", httpResult.Error)
	}
	return fmt.Errorf("http test failed")
}

// TestUDP implements scheduler.ProxyOutboundTester.
func (h *ProxyOutboundHandler) TestUDP(name string) error {
	if name == "" {
		return fmt.Errorf("name is required")
	}

	cfg, ok := h.configMgr.GetOutbound(name)
	if !ok {
		return fmt.Errorf("proxy outbound not found: %s", name)
	}

	result := h.testMCBEServer(cfg, defaultMCBEUDPTestAddress)
	available := result.Success

	if outbound, ok := h.configMgr.GetOutbound(name); ok {
		udp := available
		outbound.SetUDPAvailable(&udp)
		if result.Success {
			outbound.UDPLatencyMs = result.LatencyMs
		} else {
			outbound.UDPLatencyMs = 0
		}
		_ = h.configMgr.UpdateOutbound(name, outbound)
	}

	if result.Success {
		return nil
	}
	if result.Error != "" {
		return fmt.Errorf("%s", result.Error)
	}
	return fmt.Errorf("udp test failed")
}

var _ interface {
	TestTCP(name string) error
	TestHTTP(name string) error
	TestUDP(name string) error
} = (*ProxyOutboundHandler)(nil)
