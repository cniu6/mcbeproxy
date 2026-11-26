package proxy

import (
	"context"
	"net"
	"testing"
	"time"

	"mcpeserverproxy/internal/config"
)

// 启动时端口被占用导致首次绑定失败，释放后恢复逻辑必须能把它拉起来，
// 而不是一直停在未监听状态直到手动保存。
func TestProxyPortRecoveryBindsAfterInitialFailure(t *testing.T) {
	// 用一个临时端口先占位，模拟重启时旧进程仍持有 socket。
	probe, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := probe.Addr().String()

	dir := t.TempDir()
	cfgMgr := config.NewProxyPortConfigManager(dir + "/proxy_ports.json")
	if err := cfgMgr.Load(); err != nil {
		t.Fatal(err)
	}
	port := &config.ProxyPortConfig{
		ID:         "web",
		Name:       "web",
		ListenAddr: addr,
		Type:       "http",
		Enabled:    true,
	}
	if err := cfgMgr.AddPort(port); err != nil {
		t.Fatal(err)
	}

	outboundMgr := NewOutboundManagerWithSingboxFactory(nil, &countingFactory{})
	mgr := NewProxyPortManager(cfgMgr, outboundMgr)
	defer mgr.Stop()

	// 端口仍被 probe 占用，首次 Start 必然失败且不监听。
	if err := mgr.Start(true); err == nil {
		t.Fatal("预期首次 Start 因端口占用而失败")
	}
	if mgr.GetActiveConnectionCountForPort("web") != 0 {
		t.Fatal("占用期间不应有活动监听")
	}

	// 释放端口（旧进程退出），恢复逻辑应当能绑定成功。
	_ = probe.Close()
	mgr.recoverMissingListeners()

	cfgMgr2, ok := mgr.configMgr.GetPort("web")
	if !ok || cfgMgr2 == nil {
		t.Fatal("端口配置丢失")
	}
	mgr.mu.Lock()
	_, listening := mgr.listeners["web"]
	mgr.mu.Unlock()
	if !listening {
		t.Fatal("释放端口后 recoverMissingListeners 未把端口拉起来")
	}

	// 重复触发恢复不能重复绑定或panic（Start 对已有 ID 去重）。
	mgr.recoverMissingListeners()
	mgr.mu.Lock()
	count := len(mgr.listeners)
	mgr.mu.Unlock()
	if count != 1 {
		t.Fatalf("恢复后应只有1个监听，实际 %d", count)
	}
}

// worker 生命周期：StartRecovery 幂等，Stop 后不再重试且能干净退出。
func TestProxyPortRecoveryWorkerLifecycle(t *testing.T) {
	dir := t.TempDir()
	cfgMgr := config.NewProxyPortConfigManager(dir + "/proxy_ports.json")
	if err := cfgMgr.Load(); err != nil {
		t.Fatal(err)
	}
	outboundMgr := NewOutboundManagerWithSingboxFactory(nil, &countingFactory{})
	mgr := NewProxyPortManager(cfgMgr, outboundMgr)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	enabled := func() bool { return true }

	mgr.StartRecovery(ctx, enabled)
	mgr.StartRecovery(ctx, enabled) // 幂等，不应起第二个 worker
	mgr.recoveryMu.Lock()
	if !mgr.recoveryOn {
		mgr.recoveryMu.Unlock()
		t.Fatal("worker 未标记为运行")
	}
	mgr.recoveryMu.Unlock()

	done := make(chan struct{})
	go func() { mgr.Stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(3 * time.Second):
		t.Fatal("Stop 未能及时结束 recovery worker")
	}
}
