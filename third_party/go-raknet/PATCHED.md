# Local patches to github.com/sandertv/go-raknet

Vendored from v1.15.2-0.20260705184311-0d1fd09e2cf6 via `replace` in go.mod.
Re-apply when upgrading.

1. **Send pacing** (`pace.go`, hooks in `conn.go`: `write` -> `sendOrQueue`,
   `sendDatagram` -> `chargePace`, `closeImmediately` drops the queue first).
   `Conn.SetSendRate(bytesPerSec)` queues fragments before they get a
   sequence number and releases them through a token bucket, so the
   retransmission timer starts only when a datagram is on the wire and resends
   share the budget. Used by mcpeserverproxy's raknet mode
   (`downstream_limit_kbps`) to keep a join burst under a cloud egress cap.
   Without it the burst is policed, resends are policed too, and goodput
   collapses (1MB through a 200KB/s policer: 19s / 55KB/s).
