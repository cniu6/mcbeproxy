package proxy

import (
	"context"
	"errors"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	hy2 "github.com/apernet/hysteria/core/v2/client"
	M "github.com/sagernet/sing/common/metadata"
)

// 上游 UDP() 不接受 context；用可控阻塞代替真实握手，验证玩家取消的隔离边界。
type isolatedHY2Client struct {
	entered  chan struct{}
	release  chan struct{}
	once     sync.Once
	calls    atomic.Int32
	closes   atomic.Int32
	late     *isolatedHY2Session
	failOnce bool
}

func newIsolatedHY2Client() *isolatedHY2Client {
	return &isolatedHY2Client{entered: make(chan struct{}), release: make(chan struct{}), late: &isolatedHY2Session{}}
}

func (c *isolatedHY2Client) TCP(string) (net.Conn, error) { return nil, errors.New("unused") }
func (c *isolatedHY2Client) UDP() (hy2.HyUDPConn, error) {
	call := c.calls.Add(1)
	c.once.Do(func() { close(c.entered) })
	<-c.release
	if c.failOnce && call == 1 {
		return nil, errors.New("connection closed")
	}
	return c.late, nil
}
func (c *isolatedHY2Client) Close() error { c.closes.Add(1); return nil }

type isolatedHY2Session struct{ closed atomic.Bool }

func (s *isolatedHY2Session) Receive() ([]byte, string, error) { return nil, "", errors.New("unused") }
func (s *isolatedHY2Session) Send([]byte, string) error        { return nil }
func (s *isolatedHY2Session) Close() error                     { s.closed.Store(true); return nil }

func TestHY2DialIsolationSuccessAndClosedRetry(t *testing.T) {
	for _, retry := range []bool{false, true} {
		t.Run(map[bool]string{false: "success", true: "closed_retry"}[retry], func(t *testing.T) {
			client := newIsolatedHY2Client()
			client.failOnce = retry
			close(client.release)
			outbound := &SingboxOutbound{hy2Client: client}
			pc, err := outbound.dialHysteria2UDP(context.Background(), M.Socksaddr{}, M.ParseSocksaddr("127.0.0.1:19132"))
			if err != nil {
				t.Fatal(err)
			}
			wantCalls := int32(1)
			if retry {
				wantCalls = 2
			}
			if got := client.calls.Load(); got != wantCalls {
				t.Errorf("UDP calls=%d, want %d", got, wantCalls)
			}
			if got := client.closes.Load(); got != 0 {
				t.Errorf("dial closed shared client: %d", got)
			}
			if err := pc.Close(); err != nil {
				t.Fatal(err)
			}
			if !client.late.closed.Load() {
				t.Error("player close did not close its UDP session")
			}
			if got := client.closes.Load(); got != 0 {
				t.Errorf("player close closed shared client: %d", got)
			}
			if err := outbound.Close(); err != nil {
				t.Fatal(err)
			}
			if err := outbound.Close(); err != nil {
				t.Fatal(err)
			}
			if got := client.closes.Load(); got != 1 {
				t.Errorf("outbound shutdown close count=%d, want 1", got)
			}
		})
	}
}

func TestHY2DialIsolationCancelKeepsSharedClient(t *testing.T) {
	client := newIsolatedHY2Client()
	defer close(client.release)
	outbound := &SingboxOutbound{hy2Client: client}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	go func() {
		pc, err := outbound.dialHysteria2UDP(ctx, M.Socksaddr{}, M.ParseSocksaddr("127.0.0.1:19132"))
		if pc != nil {
			_ = pc.Close()
		}
		done <- err
	}()
	select {
	case <-client.entered:
	case <-time.After(time.Second):
		t.Fatal("dial did not enter UDP()")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancel error = %v", err)
		}
	case <-time.After(time.Second):
		t.Error("cancelled caller is stuck waiting for shared UDP()")
	}
	if got := client.closes.Load(); got != 0 {
		t.Fatalf("player cancellation closed shared client %d times", got)
	}
}

func TestHY2DialIsolationWaiterCancelsWithoutExtraWorker(t *testing.T) {
	client := newIsolatedHY2Client()
	outbound := &SingboxOutbound{hy2Client: client}
	ctx, cancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() {
		pc, err := outbound.dialHysteria2UDP(ctx, M.Socksaddr{}, M.ParseSocksaddr("127.0.0.1:19132"))
		if pc != nil {
			_ = pc.Close()
		}
		first <- err
	}()
	<-client.entered
	cancel()
	defer close(client.release)
	waitCtx, waitCancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer waitCancel()
	second := make(chan error, 1)
	go func() {
		pc, err := outbound.dialHysteria2UDP(waitCtx, M.Socksaddr{}, M.ParseSocksaddr("127.0.0.1:19133"))
		if pc != nil {
			_ = pc.Close()
		}
		second <- err
	}()
	select {
	case err := <-second:
		if !errors.Is(err, context.DeadlineExceeded) {
			t.Errorf("waiter error = %v", err)
		}
	case <-time.After(time.Second):
		t.Error("cancelled waiter blocked on outbound mutex")
	}
	if got := client.calls.Load(); got != 1 {
		t.Errorf("unbounded pending UDP workers: calls=%d", got)
	}
	if got := client.closes.Load(); got != 0 {
		t.Errorf("cancel closed shared client: %d", got)
	}
	select {
	case <-first:
	case <-time.After(time.Second):
		t.Error("first cancelled waiter did not return")
	}
}

func TestHY2DialIsolationLateSessionIsClosed(t *testing.T) {
	client := newIsolatedHY2Client()
	outbound := &SingboxOutbound{hy2Client: client}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		pc, _ := outbound.dialHysteria2UDP(ctx, M.Socksaddr{}, M.ParseSocksaddr("127.0.0.1:19132"))
		if pc != nil {
			_ = pc.Close()
		}
		close(done)
	}()
	<-client.entered
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Error("cancel did not return promptly")
	}
	close(client.release)
	deadline := time.Now().Add(time.Second)
	for !client.late.closed.Load() && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !client.late.closed.Load() {
		t.Error("late UDP session leaked after caller cancellation")
	}
	if got := client.closes.Load(); got != 0 {
		t.Errorf("late cleanup closed shared client: %d", got)
	}
}
