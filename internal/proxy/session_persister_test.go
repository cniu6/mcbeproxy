package proxy

import (
	"sync"
	"testing"
	"time"

	"mcpeserverproxy/internal/session"
)

func TestSessionPersisterIsAsyncOrderedAndFlushes(t *testing.T) {
	release := make(chan struct{})
	var mu sync.Mutex
	var order []string
	sp := newSessionPersister(func(s *session.Session) {
		<-release // a slow database write
		mu.Lock()
		order = append(order, s.ClientAddr)
		mu.Unlock()
	})

	start := time.Now()
	for _, addr := range []string{"a", "b", "c"} {
		sp.Enqueue(&session.Session{ClientAddr: addr})
	}
	if time.Since(start) > 50*time.Millisecond {
		t.Fatal("Enqueue blocked on the database write")
	}
	close(release)
	if !sp.Flush(2 * time.Second) {
		t.Fatal("Flush timed out")
	}
	mu.Lock()
	defer mu.Unlock()
	if len(order) != 3 || order[0] != "a" || order[1] != "b" || order[2] != "c" {
		t.Fatalf("persisted order = %v", order)
	}
}
