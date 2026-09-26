package splithttp

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptrace"
	"sync"

	"github.com/xtls/xray-core/common"
	"github.com/xtls/xray-core/common/buf"
	"github.com/xtls/xray-core/common/errors"
	"github.com/xtls/xray-core/common/net"
	"github.com/xtls/xray-core/common/signal/done"
)

// interface to abstract between use of browser dialer, vs net/http
type DialerClient interface {
	IsClosed() bool

	// ctx, url, sessionId, body, uploadOnly
	OpenStream(context.Context, string, string, io.Reader, bool) (io.ReadCloser, net.Addr, net.Addr, error)

	// ctx, url, sessionId, seqStr, body, contentLength
	PostPacket(context.Context, string, string, string, buf.MultiBuffer) error
}

// implements splithttp.DialerClient in terms of direct network connections
type DefaultDialerClient struct {
	transportConfig *Config
	client          *http.Client
	closed          bool
	httpVersion     string
	// pool of net.Conn, created using dialUploadConn
	uploadRawPool  *sync.Pool
	dialUploadConn func(ctxInner context.Context) (net.Conn, error)
}

func (c *DefaultDialerClient) IsClosed() bool {
	return c.closed
}

func (c *DefaultDialerClient) OpenStream(ctx context.Context, url string, sessionId string, body io.Reader, uploadOnly bool) (wrc io.ReadCloser, remoteAddr, localAddr net.Addr, err error) {
	// this is done when the TCP/UDP connection to the server was established,
	// and we can unblock the Dial function and print correct net addresses in
	// logs
	gotConn := done.New()
	ctx = httptrace.WithClientTrace(ctx, &httptrace.ClientTrace{
		GotConn: func(connInfo httptrace.GotConnInfo) {
			remoteAddr = connInfo.Conn.RemoteAddr()
			localAddr = connInfo.Conn.LocalAddr()
			gotConn.Close()
		},
	})

	method := "GET" // stream-down
	if body != nil {
		method = c.transportConfig.GetNormalizedUplinkHTTPMethod() // stream-up/one
	}
	req, _ := http.NewRequestWithContext(context.WithoutCancel(ctx), method, url, body)
	c.transportConfig.FillStreamRequest(req, sessionId, "")

	wrc = &WaitReadCloser{Wait: make(chan struct{})}
	go func() {
		resp, err := c.client.Do(req)
		if err != nil {
			if !uploadOnly { // stream-down is enough
				c.closed = true
				errors.LogInfoInner(ctx, err, "failed to "+method+" "+url)
			}
			gotConn.Close()
			wrc.Close()
			return
		}
		if resp.StatusCode != 200 && !uploadOnly {
			errors.LogInfo(ctx, "unexpected status ", resp.StatusCode)
		}
		if resp.StatusCode != 200 || uploadOnly { // stream-up
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close() // if it is called immediately, the upload will be interrupted also
			wrc.Close()
			return
		}
		wrc.(*WaitReadCloser).Set(resp.Body)
	}()

	<-gotConn.Wait()
	return
}

func (c *DefaultDialerClient) PostPacket(ctx context.Context, url string, sessionId string, seqStr string, payload buf.MultiBuffer) error {
	method := c.transportConfig.GetNormalizedUplinkHTTPMethod()
	req, err := http.NewRequestWithContext(context.WithoutCancel(ctx), method, url, nil)
	if err != nil {
		return err
	}
	c.transportConfig.FillPacketRequest(req, sessionId, seqStr, payload)

	if c.httpVersion != "1.1" {
		resp, err := c.client.Do(req)
		if err != nil {
			c.closed = true
			return err
		}

		io.Copy(io.Discard, resp.Body)
		defer resp.Body.Close()

		if resp.StatusCode != 200 {
			return errors.New("bad status code:", resp.Status)
		}
	} else {
		// stringify the entire HTTP/1.1 request so it can be
		// safely retried. if instead req.Write is called multiple
		// times, the body is already drained after the first
		// request
		requestBuff := new(bytes.Buffer)
		requestBuff.Grow(512 + int(req.ContentLength))
		common.Must(req.Write(requestBuff))

		var uploadConn any
		var h1UploadConn *H1Conn

		for {
			uploadConn = c.uploadRawPool.Get()
			newConnection := uploadConn == nil
			if newConnection {
				newConn, err := c.dialUploadConn(context.WithoutCancel(ctx))
				if err != nil {
					return err
				}
				h1UploadConn = NewH1Conn(newConn)
				uploadConn = h1UploadConn
			} else {
				h1UploadConn = uploadConn.(*H1Conn)

				// TODO: Replace 0 here with a config value later
				// Or add some other condition for optimization purposes
				if h1UploadConn.UnreadedResponsesCount > 0 {
					resp, err := http.ReadResponse(h1UploadConn.RespBufReader, req)
					if err != nil {
						c.closed = true
						return fmt.Errorf("error while reading response: %s", err.Error())
					}
					io.Copy(io.Discard, resp.Body)
					defer resp.Body.Close()
					if resp.StatusCode != 200 {
						return fmt.Errorf("got non-200 error response code: %d", resp.StatusCode)
					}
				}
			}

			_, err := h1UploadConn.Write(requestBuff.Bytes())
			// if the write failed, we try another connection from
			// the pool, until the write on a new connection fails.
			// failed writes to a pooled connection are normal when
			// the connection has been closed in the meantime.
			if err == nil {
				break
			} else if newConnection {
				return err
			}
		}

		c.uploadRawPool.Put(uploadConn)
	}

	return nil
}

// WaitReadCloser is filled by Set from the response goroutine while Read and
// Close may run on other goroutines.
//
// PATCHED (mcpeserverproxy, third_party/xray-core): upstream read and wrote
// ReadCloser without synchronisation (Read peeked at it before waiting on
// Wait) and could close Wait twice (Set vs Close, recovered by a panic
// handler). All access now goes through mu; Wait is closed exactly once.
type WaitReadCloser struct {
	Wait chan struct{}
	io.ReadCloser

	mu         sync.Mutex
	waitClosed bool
	closed     bool
}

func (w *WaitReadCloser) Set(rc io.ReadCloser) {
	w.mu.Lock()
	if w.closed {
		w.mu.Unlock()
		rc.Close()
		return
	}
	w.ReadCloser = rc
	if !w.waitClosed {
		w.waitClosed = true
		close(w.Wait)
	}
	w.mu.Unlock()
}

func (w *WaitReadCloser) Read(b []byte) (int, error) {
	<-w.Wait
	w.mu.Lock()
	rc := w.ReadCloser
	w.mu.Unlock()
	if rc == nil {
		return 0, io.ErrClosedPipe
	}
	return rc.Read(b)
}

func (w *WaitReadCloser) Close() error {
	w.mu.Lock()
	w.closed = true
	rc := w.ReadCloser
	if !w.waitClosed {
		w.waitClosed = true
		close(w.Wait)
	}
	w.mu.Unlock()
	if rc != nil {
		return rc.Close()
	}
	return nil
}
