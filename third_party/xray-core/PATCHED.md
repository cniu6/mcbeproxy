# Patched copy of github.com/xtls/xray-core v1.260327.0

Used through `replace` in ../../go.mod. Only change:

- `transport/internet/splithttp/client.go`: `WaitReadCloser` made race-free
  (mutex around ReadCloser, Wait closed exactly once). Found by
  `go test -race -run TestUpgradeToXHTTP_DialsLocalSplitHTTP ./internal/proxy`.

When upgrading xray-core, re-copy the new version and re-apply, or drop the
replace if upstream has fixed it.
