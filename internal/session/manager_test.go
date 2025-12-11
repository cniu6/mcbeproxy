package session

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/leanovate/gopter"
	"github.com/leanovate/gopter/gen"
	"github.com/leanovate/gopter/prop"
)

// **Feature: mcpe-server-proxy, Property 2: Session Uniqueness**
// **Validates: Requirements 2.1**
// For any client address (ip:port), there SHALL exist at most one active session
// in the session manager at any given time.
func TestSessionUniqueness(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("Each client address has at most one session", prop.ForAll(
		func(clientAddrs []string, serverID string) bool {
			sm := NewSessionManager(time.Minute * 5)

			// Create sessions for all client addresses (may have duplicates)
			for _, addr := range clientAddrs {
				sm.GetOrCreate(addr, serverID)
			}

			// Verify uniqueness: count sessions per address
			addressCount := make(map[string]int)
			sessions := sm.GetAllSessions()
			for _, session := range sessions {
				addressCount[session.ClientAddr]++
			}

			// Each address should appear at most once
			for addr, count := range addressCount {
				if count > 1 {
					t.Logf("Address %s has %d sessions, expected 1", addr, count)
					return false
				}
			}

			return true
		},
		gen.SliceOf(genClientAddr()),
		gen.AlphaString(),
	))

	properties.Property("GetOrCreate returns same session for same address", prop.ForAll(
		func(clientAddr, serverID string) bool {
			sm := NewSessionManager(time.Minute * 5)

			// Create session first time
			session1, created1 := sm.GetOrCreate(clientAddr, serverID)
			if !created1 {
				t.Log("First GetOrCreate should create new session")
				return false
			}

			// Get same session second time
			session2, created2 := sm.GetOrCreate(clientAddr, serverID)
			if created2 {
				t.Log("Second GetOrCreate should not create new session")
				return false
			}

			// Should be the same session
			if session1.ID != session2.ID {
				t.Logf("Session IDs differ: %s vs %s", session1.ID, session2.ID)
				return false
			}

			return true
		},
		genClientAddr(),
		gen.AlphaString(),
	))

	properties.TestingRun(t)
}

// genClientAddr generates valid client address strings in ip:port format.
func genClientAddr() gopter.Gen {
	return gopter.CombineGens(
		gen.IntRange(1, 255),
		gen.IntRange(0, 255),
		gen.IntRange(0, 255),
		gen.IntRange(1, 255),
		gen.IntRange(1024, 65535),
	).Map(func(values []any) string {
		return fmt.Sprintf("%d.%d.%d.%d:%d",
			values[0].(int),
			values[1].(int),
			values[2].(int),
			values[3].(int),
			values[4].(int))
	})
}

// **Feature: mcpe-server-proxy, Property 13: Concurrent Session Safety**
// **Validates: Requirements 1.5, 1.6**
// For any sequence of concurrent operations on the session manager (create, get, update, delete),
// the session map SHALL remain in a consistent state without data races.
func TestConcurrentSessionSafety(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("Concurrent operations maintain consistency", prop.ForAll(
		func(numGoroutines, opsPerGoroutine int) bool {
			sm := NewSessionManager(time.Minute * 5)
			clientAddrs := []string{
				"192.168.1.1:19132",
				"192.168.1.2:19133",
				"192.168.1.3:19134",
				"192.168.1.4:19135",
				"192.168.1.5:19136",
			}

			var wg sync.WaitGroup
			errChan := make(chan error, numGoroutines*opsPerGoroutine)

			// Launch concurrent goroutines
			for i := 0; i < numGoroutines; i++ {
				wg.Add(1)
				go func(goroutineID int) {
					defer wg.Done()
					for j := 0; j < opsPerGoroutine; j++ {
						addr := clientAddrs[(goroutineID+j)%len(clientAddrs)]
						op := (goroutineID + j) % 5

						switch op {
						case 0: // GetOrCreate
							_, _ = sm.GetOrCreate(addr, "server1")
						case 1: // Get
							_, _ = sm.Get(addr)
						case 2: // UpdateActivity
							sm.UpdateActivity(addr)
						case 3: // GetAllSessions
							_ = sm.GetAllSessions()
						case 4: // Count
							_ = sm.Count()
						}
					}
				}(i)
			}

			wg.Wait()
			close(errChan)

			// Check for errors
			for err := range errChan {
				if err != nil {
					t.Logf("Error during concurrent operation: %v", err)
					return false
				}
			}

			// Verify final state is consistent
			sessions := sm.GetAllSessions()
			count := sm.Count()

			if len(sessions) != count {
				t.Logf("Inconsistent state: GetAllSessions returned %d, Count returned %d",
					len(sessions), count)
				return false
			}

			// Verify no duplicate addresses
			addrSet := make(map[string]bool)
			for _, s := range sessions {
				if addrSet[s.ClientAddr] {
					t.Logf("Duplicate session for address: %s", s.ClientAddr)
					return false
				}
				addrSet[s.ClientAddr] = true
			}

			return true
		},
		gen.IntRange(2, 10),  // numGoroutines
		gen.IntRange(10, 50), // opsPerGoroutine
	))

	properties.Property("Concurrent create and remove maintains consistency", prop.ForAll(
		func(numOps int) bool {
			sm := NewSessionManager(time.Minute * 5)
			addr := "192.168.1.100:19132"

			var wg sync.WaitGroup
			createCount := int64(0)
			removeCount := int64(0)

			// Half goroutines create, half remove
			for i := 0; i < numOps; i++ {
				wg.Add(2)

				// Creator goroutine
				go func() {
					defer wg.Done()
					_, created := sm.GetOrCreate(addr, "server1")
					if created {
						atomic.AddInt64(&createCount, 1)
					}
				}()

				// Remover goroutine
				go func() {
					defer wg.Done()
					err := sm.Remove(addr)
					if err == nil {
						atomic.AddInt64(&removeCount, 1)
					}
				}()
			}

			wg.Wait()

			// Final state should be consistent
			_, exists := sm.Get(addr)
			count := sm.Count()

			// Either session exists and count is 1, or doesn't exist and count is 0
			if exists && count != 1 {
				t.Logf("Session exists but count is %d", count)
				return false
			}
			if !exists && count != 0 {
				t.Logf("Session doesn't exist but count is %d", count)
				return false
			}

			return true
		},
		gen.IntRange(5, 20), // numOps
	))

	properties.TestingRun(t)
}

// **Feature: mcpe-server-proxy, Property 3: Byte Counter Accuracy**
// **Validates: Requirements 2.2**
// For any session, the sum of bytes_up SHALL equal the total bytes of all packets
// forwarded from client to remote, and bytes_down SHALL equal the total bytes of
// all packets forwarded from remote to client.
func TestByteCounterAccuracy(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("BytesUp accumulates correctly", prop.ForAll(
		func(byteCounts []int64) bool {
			session := &Session{
				ID:        "test-session",
				StartTime: time.Now(),
				LastSeen:  time.Now(),
			}

			expectedTotal := int64(0)
			for _, count := range byteCounts {
				// Only add positive values
				if count > 0 {
					session.AddBytesUp(count)
					expectedTotal += count
				}
			}

			return session.BytesUp == expectedTotal
		},
		gen.SliceOf(gen.Int64Range(0, 1<<20)), // Up to 1MB per packet
	))

	properties.Property("BytesDown accumulates correctly", prop.ForAll(
		func(byteCounts []int64) bool {
			session := &Session{
				ID:        "test-session",
				StartTime: time.Now(),
				LastSeen:  time.Now(),
			}

			expectedTotal := int64(0)
			for _, count := range byteCounts {
				if count > 0 {
					session.AddBytesDown(count)
					expectedTotal += count
				}
			}

			return session.BytesDown == expectedTotal
		},
		gen.SliceOf(gen.Int64Range(0, 1<<20)),
	))

	properties.Property("Concurrent byte updates are accurate", prop.ForAll(
		func(numGoroutines int, updatesPerGoroutine int, bytesPerUpdate int64) bool {
			session := &Session{
				ID:        "test-session",
				StartTime: time.Now(),
				LastSeen:  time.Now(),
			}

			var wg sync.WaitGroup
			expectedUp := int64(numGoroutines) * int64(updatesPerGoroutine) * bytesPerUpdate
			expectedDown := int64(numGoroutines) * int64(updatesPerGoroutine) * bytesPerUpdate

			for i := 0; i < numGoroutines; i++ {
				wg.Add(1)
				go func() {
					defer wg.Done()
					for j := 0; j < updatesPerGoroutine; j++ {
						session.AddBytesUp(bytesPerUpdate)
						session.AddBytesDown(bytesPerUpdate)
					}
				}()
			}

			wg.Wait()

			if session.BytesUp != expectedUp {
				t.Logf("BytesUp mismatch: got %d, expected %d", session.BytesUp, expectedUp)
				return false
			}
			if session.BytesDown != expectedDown {
				t.Logf("BytesDown mismatch: got %d, expected %d", session.BytesDown, expectedDown)
				return false
			}

			return true
		},
		gen.IntRange(2, 10),      // numGoroutines
		gen.IntRange(10, 100),    // updatesPerGoroutine
		gen.Int64Range(1, 10000), // bytesPerUpdate
	))

	properties.TestingRun(t)
}

// **Feature: mcpe-server-proxy, Property 4: Session Timestamp Invariant**
// **Validates: Requirements 2.3, 2.4**
// For any session, start_time SHALL be less than or equal to lastSeen,
// and lastSeen SHALL be updated to a value greater than or equal to the
// previous lastSeen on any packet activity.
func TestSessionTimestampInvariant(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("StartTime <= LastSeen always holds", prop.ForAll(
		func(numUpdates int) bool {
			now := time.Now()
			session := &Session{
				ID:        "test-session",
				StartTime: now,
				LastSeen:  now,
			}

			// Perform multiple updates
			for i := 0; i < numUpdates; i++ {
				session.UpdateLastSeen()
				time.Sleep(time.Microsecond) // Small delay to ensure time progresses
			}

			// Invariant: StartTime <= LastSeen
			session.mu.Lock()
			startTime := session.StartTime
			lastSeen := session.LastSeen
			session.mu.Unlock()

			if startTime.After(lastSeen) {
				t.Logf("Invariant violated: StartTime (%v) > LastSeen (%v)",
					startTime, lastSeen)
				return false
			}

			return true
		},
		gen.IntRange(1, 20),
	))

	properties.Property("LastSeen monotonically increases", prop.ForAll(
		func(numUpdates int) bool {
			now := time.Now()
			session := &Session{
				ID:        "test-session",
				StartTime: now,
				LastSeen:  now,
			}

			session.mu.Lock()
			previousLastSeen := session.LastSeen
			session.mu.Unlock()

			for i := 0; i < numUpdates; i++ {
				time.Sleep(time.Microsecond) // Ensure time progresses
				session.UpdateLastSeen()

				session.mu.Lock()
				currentLastSeen := session.LastSeen
				session.mu.Unlock()

				// LastSeen should be >= previous value
				if currentLastSeen.Before(previousLastSeen) {
					t.Logf("LastSeen decreased: %v -> %v", previousLastSeen, currentLastSeen)
					return false
				}

				previousLastSeen = currentLastSeen
			}

			return true
		},
		gen.IntRange(1, 20),
	))

	properties.Property("New session has StartTime == LastSeen", prop.ForAll(
		func(clientAddr, serverID string) bool {
			sm := NewSessionManager(time.Minute * 5)
			session, _ := sm.GetOrCreate(clientAddr, serverID)

			session.mu.Lock()
			startTime := session.StartTime
			lastSeen := session.LastSeen
			session.mu.Unlock()

			// For a new session, StartTime should equal LastSeen
			if !startTime.Equal(lastSeen) {
				t.Logf("New session: StartTime (%v) != LastSeen (%v)",
					startTime, lastSeen)
				return false
			}

			return true
		},
		genClientAddr(),
		gen.AlphaString(),
	))

	properties.TestingRun(t)
}

// **Feature: mcpe-server-proxy, Property 5: Idle Session Cleanup**
// **Validates: Requirements 2.6**
// For any session where (current_time - lastSeen) exceeds idle_timeout,
// the session SHALL be marked for garbage collection.
func TestIdleSessionCleanup(t *testing.T) {
	parameters := gopter.DefaultTestParameters()
	parameters.MinSuccessfulTests = 100
	parameters.Rng.Seed(time.Now().UnixNano())

	properties := gopter.NewProperties(parameters)

	properties.Property("Sessions exceeding idle timeout are identified for cleanup", prop.ForAll(
		func(numSessions int, idleTimeoutMs int) bool {
			idleTimeout := time.Duration(idleTimeoutMs) * time.Millisecond
			sm := NewSessionManager(idleTimeout)

			// Create sessions
			for i := 0; i < numSessions; i++ {
				addr := fmt.Sprintf("192.168.1.%d:%d", i%256, 19132+i)
				sm.GetOrCreate(addr, "server1")
			}

			// Wait for sessions to become idle
			time.Sleep(idleTimeout + time.Millisecond*10)

			// All sessions should be identified as idle
			idleSessions := sm.GetIdleSessions(idleTimeout)

			if len(idleSessions) != numSessions {
				t.Logf("Expected %d idle sessions, got %d", numSessions, len(idleSessions))
				return false
			}

			return true
		},
		gen.IntRange(1, 10),  // numSessions
		gen.IntRange(10, 50), // idleTimeoutMs
	))

	properties.Property("Active sessions are not cleaned up", prop.ForAll(
		func(numSessions int) bool {
			idleTimeout := time.Minute * 5 // Long timeout
			sm := NewSessionManager(idleTimeout)

			// Create sessions
			for i := 0; i < numSessions; i++ {
				addr := fmt.Sprintf("192.168.1.%d:%d", i%256, 19132+i)
				sm.GetOrCreate(addr, "server1")
			}

			// Immediately check - no sessions should be idle
			idleSessions := sm.GetIdleSessions(idleTimeout)

			if len(idleSessions) != 0 {
				t.Logf("Expected 0 idle sessions, got %d", len(idleSessions))
				return false
			}

			// Cleanup should remove nothing
			removed := sm.CleanupNow()
			if removed != 0 {
				t.Logf("Expected 0 removed sessions, got %d", removed)
				return false
			}

			// All sessions should still exist
			if sm.Count() != numSessions {
				t.Logf("Expected %d sessions, got %d", numSessions, sm.Count())
				return false
			}

			return true
		},
		gen.IntRange(1, 20),
	))

	properties.Property("CleanupNow removes only idle sessions", prop.ForAll(
		func(numActive, numIdle int, idleTimeoutMs int) bool {
			idleTimeout := time.Duration(idleTimeoutMs) * time.Millisecond
			sm := NewSessionManager(idleTimeout)

			// Create sessions that will become idle
			idleAddrs := make([]string, numIdle)
			for i := 0; i < numIdle; i++ {
				addr := fmt.Sprintf("10.0.0.%d:%d", i%256, 19132+i)
				idleAddrs[i] = addr
				sm.GetOrCreate(addr, "server1")
			}

			// Wait for idle timeout
			time.Sleep(idleTimeout + time.Millisecond*10)

			// Create active sessions (after the wait)
			activeAddrs := make([]string, numActive)
			for i := 0; i < numActive; i++ {
				addr := fmt.Sprintf("192.168.1.%d:%d", i%256, 19132+i)
				activeAddrs[i] = addr
				sm.GetOrCreate(addr, "server1")
			}

			// Cleanup should remove only idle sessions
			removed := sm.CleanupNow()

			if removed != numIdle {
				t.Logf("Expected %d removed, got %d", numIdle, removed)
				return false
			}

			// Only active sessions should remain
			if sm.Count() != numActive {
				t.Logf("Expected %d remaining, got %d", numActive, sm.Count())
				return false
			}

			// Verify active sessions still exist
			for _, addr := range activeAddrs {
				if _, exists := sm.Get(addr); !exists {
					t.Logf("Active session %s was incorrectly removed", addr)
					return false
				}
			}

			// Verify idle sessions were removed
			for _, addr := range idleAddrs {
				if _, exists := sm.Get(addr); exists {
					t.Logf("Idle session %s was not removed", addr)
					return false
				}
			}

			return true
		},
		gen.IntRange(1, 10),  // numActive
		gen.IntRange(1, 10),  // numIdle
		gen.IntRange(10, 50), // idleTimeoutMs
	))

	properties.TestingRun(t)
}
