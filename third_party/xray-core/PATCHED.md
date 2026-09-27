# Patched copy of github.com/xtls/xray-core v1.260327.0

Used through `replace` in ../../go.mod. All changes fix data races found with
`go test -race` (upstream v1.260327.0 is the latest release and has them):

- `transport/internet/splithttp/client.go`: `WaitReadCloser` made race-free
  (mutex around ReadCloser, Wait closed exactly once). Found by
  `go test -race -run TestUpgradeToXHTTP_DialsLocalSplitHTTP ./internal/proxy`.
- `transport/internet/splithttp/dialer.go`: `uploadWriter.Write` read `buff.Len()`
  after handing the buffer to the upload goroutine (use after ownership
  transfer); the length is now taken first. Found by the same test.
- `transport/internet/splithttp/upload_queue.go` (XHTTP server side): `reader`
  and `closed` were written by Close under a lock and read by Read without
  one; they now have their own mutex (Push's mutex cannot be used: Push holds
  it while blocked on the channel Read drains).
- `transport/internet/tls/config.go` (TLS server side): the certificate
  hot-reload/OCSP goroutine wrote certificate slice elements and mutated
  `OCSPStaple` in place while handshakes read them. Certificates now live in a
  copy-on-write store published atomically.
- `transport/internet/splithttp/splithttp_test.go`: the test's own
  `serverClosed` flag is now atomic.

Verification: `go test -race ./transport/internet/splithttp/` passes
repeatedly (the unpatched release fails it), and
`go test -race -skip TestECH ./transport/internet/tls/` passes (TestECHDial
needs Internet access to 1.1.1.1 and fails offline with or without patches).

When upgrading xray-core, re-copy the new version and re-apply, or drop the
replace if upstream has fixed these.
