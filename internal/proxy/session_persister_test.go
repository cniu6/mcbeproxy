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

func TestSessionPersisterStats(t *testing.T) {
	release := make(chan struct{})
	var once sync.Once
	sp := newSessionPersisterWithQueue(func(s *session.Session) {
		if s.ClientAddr == "boom" {
			panic("db exploded")
		}
		<-release
	}, 2)

	// "a" occupies the writer (wait until it has been taken off the queue), "b"
	// and "c" fill the queue, "d" overflows and is written inline — the writer
	// is released shortly after so the inline write can return.
	sp.Enqueue(&session.Session{ClientAddr: "a"})
	deadline := time.Now().Add(2 * time.Second)
	for sp.Stats().QueueDepth != 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	sp.Enqueue(&session.Session{ClientAddr: "b"})
	sp.Enqueue(&session.Session{ClientAddr: "c"})
	deadline = time.Now().Add(2 * time.Second)
	for sp.Stats().QueueDepth < 2 && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	go func() { time.Sleep(50 * time.Millisecond); once.Do(func() { close(release) }) }()
	sp.Enqueue(&session.Session{ClientAddr: "d"}) // queue full → inline
	sp.Enqueue(&session.Session{ClientAddr: "boom"})
	if !sp.Flush(2 * time.Second) {
		t.Fatal("Flush timed out")
	}

	st := sp.Stats()
	if st.Enqueued != 5 || st.Written != 4 || st.Panics != 1 || st.InlineWrites < 1 || st.QueueDepth != 0 || st.QueueCapacity != 2 {
		t.Fatalf("stats = %+v", st)
	}
	// The persister goroutine survived the panic and still writes.
	sp.Enqueue(&session.Session{ClientAddr: "after"})
	if !sp.Flush(2*time.Second) || sp.Stats().Written != 5 {
		t.Fatalf("persister stopped after a panic: %+v", sp.Stats())
	}
}
