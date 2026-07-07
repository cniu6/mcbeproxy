package session

import (
	"encoding/json"
	"testing"
	"time"
)

func TestSessionToDTOIncludesLastSeenAndIdleSeconds(t *testing.T) {
	now := time.Now()
	start := now.Add(-5 * time.Minute)
	lastSeen := now.Add(-90 * time.Second)
	sess := &Session{
		ID:         "dto-session-1",
		ClientAddr: "127.0.0.1:19132",
		ServerID:   "server-1",
		BytesUp:    10,
		BytesDown:  20,
		StartTime:  start,
		LastSeen:   lastSeen,
	}

	dto := sess.ToDTO()
	if !dto.LastSeen.Equal(lastSeen) {
		t.Fatalf("LastSeen = %v, want %v", dto.LastSeen, lastSeen)
	}
	if dto.IdleSeconds < 89 || dto.IdleSeconds > 95 {
		t.Fatalf("IdleSeconds = %d, want about 90", dto.IdleSeconds)
	}
	if dto.Duration < 299 || dto.Duration > 305 {
		t.Fatalf("Duration = %d, want about 300", dto.Duration)
	}

	payload, err := json.Marshal(dto)
	if err != nil {
		t.Fatalf("marshal dto: %v", err)
	}
	var decoded map[string]any
	if err := json.Unmarshal(payload, &decoded); err != nil {
		t.Fatalf("unmarshal dto: %v", err)
	}
	if _, ok := decoded["last_seen"]; !ok {
		t.Fatalf("JSON missing last_seen: %s", payload)
	}
	if got, ok := decoded["idle_seconds"].(float64); !ok || got < 89 || got > 95 {
		t.Fatalf("JSON idle_seconds = %#v, want about 90; payload=%s", decoded["idle_seconds"], payload)
	}
}
