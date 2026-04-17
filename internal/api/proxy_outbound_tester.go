package api

import (
	"context"
	"fmt"
	"time"

	"mcpeserverproxy/internal/config"
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

	h.updateOutboundRuntime(name, func(outbound *config.ProxyOutbound) {
		if err == nil {
			outbound.SetTCPLatencyMs(latency)
		} else {
			outbound.SetTCPLatencyMs(0)
		}
	})

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

	dialer, err := h.singboxFactory.CreateDialer(context.Background(), cfg)
	if err != nil {
		return fmt.Errorf("failed to create proxy dialer: %w", err)
	}
	defer dialer.Close()

	target := DefaultHTTPTestTargets[0]
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	httpResult := h.testHTTPThroughProxy(ctx, cfg, dialer, target)

	h.updateOutboundRuntime(name, func(outbound *config.ProxyOutbound) {
		if httpResult.Success {
			outbound.SetHTTPLatencyMs(httpResult.LatencyMs)
		} else {
			outbound.SetHTTPLatencyMs(0)
		}
	})

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

	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	result := h.testMCBEServer(ctx, cfg, defaultMCBEUDPTestAddress)
	available := result.Success

	h.updateOutboundRuntime(name, func(outbound *config.ProxyOutbound) {
		udp := available
		outbound.SetUDPAvailable(&udp)
		if result.Success {
			outbound.SetUDPLatencyMs(result.LatencyMs)
		} else {
			outbound.SetUDPLatencyMs(0)
		}
	})

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
