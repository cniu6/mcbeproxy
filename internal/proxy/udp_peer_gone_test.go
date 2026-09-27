package proxy

import (
	"testing"
	"time"
)

func TestIsUDPPeerGone(t *testing.T) {
	now := time.Now()
	ns := func(d time.Duration) int64 { return now.Add(-d).UnixNano() }
	cases := []struct {
		name     string
		up, down int64
		want     bool
	}{
		{"target still sending, client silent 20s", ns(20 * time.Second), ns(time.Second), true},
		{"client silent 10s only", ns(10 * time.Second), ns(time.Second), false},
		{"both quiet (idle, not dead)", ns(60 * time.Second), ns(59 * time.Second), false},
		{"never saw client", 0, ns(time.Second), false},
		{"active", ns(100 * time.Millisecond), ns(50 * time.Millisecond), false},
	}
	for _, c := range cases {
		if got := isUDPPeerGone(c.up, c.down, now); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}
