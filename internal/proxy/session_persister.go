package proxy

import (
	"time"

	"mcpeserverproxy/internal/logger"
	"mcpeserverproxy/internal/session"
)

// sessionPersisterQueue bounds sessions waiting to be written.
const sessionPersisterQueue = 4096

// sessionPersister writes ended sessions to the database on one background
// goroutine. A session ends from inside packet loops (a client's RakNet
// disconnect is handled on the raw_udp receive loop), and persisting there —
// several SQLite writes with retry sleeps — froze every other player on that
// server. One writer keeps the original order and avoids concurrent writes.
type sessionPersister struct {
	jobs    chan sessionPersistJob
	persist func(*session.Session)
}

type sessionPersistJob struct {
	sess    *session.Session
	flushed chan struct{} // non-nil for a Flush marker
}

func newSessionPersister(persist func(*session.Session)) *sessionPersister {
	sp := &sessionPersister{jobs: make(chan sessionPersistJob, sessionPersisterQueue), persist: persist}
	go func() {
		defer logger.CapturePanic("session-persister")
		for job := range sp.jobs {
			if job.flushed != nil {
				close(job.flushed)
				continue
			}
			sp.persist(job.sess)
		}
	}()
	return sp
}

// Enqueue schedules sess for persistence without blocking the caller. If the
// queue is full the session is written inline rather than dropped.
func (sp *sessionPersister) Enqueue(sess *session.Session) {
	select {
	case sp.jobs <- sessionPersistJob{sess: sess}:
	default:
		logger.Warn("Session persist queue full (%d); writing inline", sessionPersisterQueue)
		sp.persist(sess)
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
