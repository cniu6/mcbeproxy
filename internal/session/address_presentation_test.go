package session

import (
	"testing"
	"time"
)

func TestSessionMappedIPv4Presentation(t *testing.T) {
	sm := NewSessionManager(time.Hour)
	s, _ := sm.GetOrCreateWithKey("owner", "[::ffff:14.19.48.240]:12123", "server")
	if got := s.ToDTO().ClientAddr; got != "14.19.48.240:12123" {
		t.Fatalf("初始地址未规范化: %s", got)
	}
	s.ApplyRelaySnapshot("[::ffff:14.19.48.241]:12345", 1, 2, time.Now())
	if got := s.Snapshot().ClientAddr; got != "14.19.48.241:12345" {
		t.Fatalf("媒体地址未规范化: %s", got)
	}
	real, _ := sm.GetOrCreateWithKey("v6", "[2001:db8::1]:1234", "server")
	if got := real.ToDTO().ClientAddr; got != "[2001:db8::1]:1234" {
		t.Fatalf("真实IPv6被破坏: %s", got)
	}
}
