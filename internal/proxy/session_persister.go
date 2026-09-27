package proxy

import (
	"sync/atomic"
	"time"

	"mcpeserverproxy/internal/logger"
	"mcpeserverproxy/internal/session"
)

// sessionPersisterQueue bounds sessions waiting to be written.
const sessionPersisterQueue = 4096

// sessionPersisterFullLogEvery rate-limits the queue-full warning.
const sessionPersisterFullLogEvery = 5 * time.Second

// sessionPersister writes ended sessions to the database on one background
// goroutine. A session ends from inside packet loops (a client's RakNet
// disconnect is handled on the raw_udp receive loop), and persisting there —
// several SQLite writes with retry sleeps — froze every other player on that
// server. One writer keeps the original order and avoids concurrent writes.
type sessionPersister struct {
	jobs    chan sessionPersistJob
	persist func(*session.Session)

	enqueued     atomic.Int64
	written      atomic.Int64
	inlineWrites atomic.Int64 // queue was full: written on the caller's goroutine
	panics       atomic.Int64
	lastFullLog  atomic.Int64
}

// SessionPersisterStats reports the session persistence pipeline, so a
// saturated database (inline writes, growing queue) is visible before it
// turns into packet-loop stalls.
type SessionPersisterStats struct {
	Enqueued      int64 `json:"enqueued"`
	Written       int64 `json:"written"`
	InlineWrites  int64 `json:"inline_writes"`
	Panics        int64 `json:"panics"`
	QueueDepth    int   `json:"queue_depth"`
	QueueCapacity int   `json:"queue_capacity"`
}

type sessionPersistJob struct {
	sess    *session.Session
	flushed chan struct{} // non-nil for a Flush marker
}

func newSessionPersister(persist func(*session.Session)) *sessionPersister {
	return newSessionPersisterWithQueue(persist, sessionPersisterQueue)
}

func newSessionPersisterWithQueue(persist func(*session.Session), queue int) *sessionPersister {
	sp := &sessionPersister{jobs: make(chan sessionPersistJob, queue), persist: persist}
	go func() {
		for job := range sp.jobs {
			if job.flushed != nil {
				close(job.flushed)
				continue
			}
			sp.write(job.sess)
		}
	}()
	return sp
}

// write persists one session; a panic in the database layer is counted and
// logged instead of killing the persister goroutine (and every later write).
func (sp *sessionPersister) write(sess *session.Session) {
	defer func() {
		if r := recover(); r != nil {
			sp.panics.Add(1)
			logger.Error("Session persist panicked (session %s dropped): %v", sess.ClientAddr, r)
		}
	}()
	sp.persist(sess)
	sp.written.Add(1)
}

// Enqueue schedules sess for persistence without blocking the caller. If the
// queue is full the session is written inline rather than dropped.
func (sp *sessionPersister) Enqueue(sess *session.Session) {
	sp.enqueued.Add(1)
	select {
	case sp.jobs <- sessionPersistJob{sess: sess}:
	default:
		n := sp.inlineWrites.Add(1)
		now := time.Now().UnixNano()
		if last := sp.lastFullLog.Load(); now-last >= int64(sessionPersisterFullLogEvery) && sp.lastFullLog.CompareAndSwap(last, now) {
			logger.Warn("Session persist queue full (%d); writing inline (total inline writes: %d) — database too slow?", sessionPersisterQueue, n)
		}
		sp.write(sess)
	}
}

// Stats returns a snapshot of the persister counters.
func (sp *sessionPersister) Stats() SessionPersisterStats {
	if sp == nil {
		return SessionPersisterStats{}
	}
	return SessionPersisterStats{
		Enqueued:      sp.enqueued.Load(),
		Written:       sp.written.Load(),
		InlineWrites:  sp.inlineWrites.Load(),
		Panics:        sp.panics.Load(),
		QueueDepth:    len(sp.jobs),
		QueueCapacity: cap(sp.jobs),
	}
}

// Flush waits until every session enqueued before the call is written, or
// until timeout.
func (sp *sessionPersister) Flush(timeout time.Duration) bool {
	marker := make(chan struct{})
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case sp.jobs <- sessionPersistJob{flushed: marker}:
	case <-timer.C:
		return false
	}
	select {
	case <-marker:
		return true
	case <-timer.C:
		return false
	}
}

// SessionPersisterStats reports the session persistence pipeline counters.
func (p *ProxyServer) SessionPersisterStats() SessionPersisterStats {
	if p == nil {
		return SessionPersisterStats{}
	}
	return p.sessionPersister.Stats()
}
