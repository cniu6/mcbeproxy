// Package session provides session management for client connections.
package session

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"

	"github.com/google/uuid"
)

// SessionManager manages active client sessions with thread-safe operations.
type SessionManager struct {
	sessions    map[string]*Session // clientAddr -> session
	mu          sync.RWMutex
	idleTimeout time.Duration
	// idleTimeoutFunc allows per-session idle timeout overrides (e.g., per server config).
	// Return <=0 to fall back to the default idleTimeout.
	idleTimeoutFunc func(session *Session) time.Duration
	// Callbacks for persistence (set by proxy server)
	OnSessionEnd func(session *Session)
}

// NewSessionManager creates a new session manager with the specified idle timeout.
func NewSessionManager(idleTimeout time.Duration) *SessionManager {
	return &SessionManager{
		sessions:    make(map[string]*Session),
		idleTimeout: idleTimeout,
	}
}

// SetIdleTimeoutFunc sets a per-session idle timeout override function.
// This is optional; if not set or returns <=0, the default idleTimeout is used.
func (sm *SessionManager) SetIdleTimeoutFunc(fn func(session *Session) time.Duration) {
	sm.mu.Lock()
	defer sm.mu.Unlock()
	sm.idleTimeoutFunc = fn
}

func (sm *SessionManager) getIdleTimeout(session *Session) time.Duration {
	if sm.idleTimeoutFunc != nil {
		v := sm.idleTimeoutFunc(session)
		if v < 0 {
			// Negative value means "never disconnect due to inactivity"
			return 0
		}
		if v > 0 {
			return v
		}
	}
	return sm.idleTimeout
}

// GetOrCreate retrieves an existing session or creates a new one for the client address.
// Returns the session and a boolean indicating if a new session was created.
func (sm *SessionManager) GetOrCreate(clientAddr string, serverID string) (*Session, bool) {
	// First try read lock for existing session
	sm.mu.RLock()
	if session, exists := sm.sessions[clientAddr]; exists {
		sm.mu.RUnlock()
		return session, false
	}
	sm.mu.RUnlock()

	// Need to create new session - acquire write lock
	sm.mu.Lock()
	defer sm.mu.Unlock()

	// Double-check after acquiring write lock
	if session, exists := sm.sessions[clientAddr]; exists {
		return session, false
	}

	// Create new session
	now := time.Now()
	session := &Session{
		ID:         uuid.New().String(),
		ClientAddr: clientAddr,
		ServerID:   serverID,
		StartTime:  now,
		LastSeen:   now,
	}

	sm.sessions[clientAddr] = session
	return session, true
}

// GetOrCreateWithKey 将中继所有者与显示地址分离；serverID 被纳入内部键。
func (sm *SessionManager) GetOrCreateWithKey(ownerKey, clientAddr, serverID string) (*Session, bool) {
	key := "relay\x00" + serverID + "\x00" + ownerKey
	sm.mu.Lock()
	defer sm.mu.Unlock()
	if s, ok := sm.sessions[key]; ok {
		return s, false
	}
	now := time.Now()
	s := &Session{ID: uuid.NewString(), ClientAddr: clientAddr, ServerID: serverID, StartTime: now, LastSeen: now}
	sm.sessions[key] = s
	return s, true
}

// RemoveIfID 必须同时匹配所有者和不可变 ID，回调在锁外且只执行一次。
func (sm *SessionManager) RemoveIfID(ownerKey, sessionID string) bool {
	sm.mu.Lock()
	var removed *Session
	for key, s := range sm.sessions {
		if s.ID == sessionID && (key == ownerKey || key == "relay\x00"+s.ServerID+"\x00"+ownerKey) {
			delete(sm.sessions, key)
			removed = s
			break
		}
	}
	sm.mu.Unlock()
	if removed == nil {
		return false
	}
	if removed.RemoteConn != nil {
		_ = removed.RemoteConn.Close()
	}
	if sm.OnSessionEnd != nil {
		sm.OnSessionEnd(removed)
	}
	return true
}

// Get retrieves a session by client address.
// Returns the session and a boolean indicating if it was found.
func (sm *SessionManager) Get(clientAddr string) (*Session, bool) {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	session, exists := sm.sessions[clientAddr]
	return session, exists
}

// Remove removes a session by client address and returns the removed session.
// Returns an error if the session doesn't exist.
func (sm *SessionManager) Remove(clientAddr string) error {
	sm.mu.Lock()
	session, exists := sm.sessions[clientAddr]
	if !exists {
		sm.mu.Unlock()
		return fmt.Errorf("session not found for client: %s", clientAddr)
	}
	delete(sm.sessions, clientAddr)
	sm.mu.Unlock()

	// Close remote connection if exists
	if session.RemoteConn != nil {
		session.RemoteConn.Close()
	}

	// Call persistence callback if set
	if sm.OnSessionEnd != nil {
		sm.OnSessionEnd(session)
	}
	return nil
}

// RemoveByID removes a session by session ID and returns true if found.
func (sm *SessionManager) RemoveByID(sessionID string) bool {
	sm.mu.Lock()
	var removed *Session
	for addr, session := range sm.sessions {
		if session.ID == sessionID {
			delete(sm.sessions, addr)
			removed = session
			break
		}
	}
	sm.mu.Unlock()

	if removed == nil {
		return false
	}

	if removed.RemoteConn != nil {
		removed.RemoteConn.Close()
	}

	if sm.OnSessionEnd != nil {
		sm.OnSessionEnd(removed)
	}

	return true
}

// RemoveByPlayerName removes all sessions for a player by display name.
// This is used to clean up stale sessions when a player reconnects.
// Returns the number of sessions removed.
func (sm *SessionManager) RemoveByPlayerName(displayName string) int {
	if displayName == "" {
		return 0
	}

	sm.mu.Lock()
	var toRemove []string
	var removed []*Session
	for addr, session := range sm.sessions {
		session.mu.Lock()
		name := session.DisplayName
		if session.IdentitySource == "nethernet_signaling" {
			name = ""
		}
		session.mu.Unlock()

		if name == displayName {
			toRemove = append(toRemove, addr)
		}
	}

	for _, addr := range toRemove {
		session := sm.sessions[addr]
		delete(sm.sessions, addr)
		removed = append(removed, session)
	}
	sm.mu.Unlock()

	for _, session := range removed {
		if session.RemoteConn != nil {
			session.RemoteConn.Close()
		}
		if sm.OnSessionEnd != nil {
			sm.OnSessionEnd(session)
		}
	}

	return len(toRemove)
}

// RemoveByXUID removes all sessions for a player by XUID.
// This is used to clean up stale sessions when a player reconnects.
// Returns the number of sessions removed.
func (sm *SessionManager) RemoveByXUID(xuid string) int {
	if xuid == "" {
		return 0
	}

	sm.mu.Lock()
	var toRemove []string
	var removed []*Session
	for addr, session := range sm.sessions {
		session.mu.Lock()
		sessionXUID := session.XUID
		if session.IdentitySource == "nethernet_signaling" {
			sessionXUID = ""
		}
		session.mu.Unlock()

		if sessionXUID == xuid {
			toRemove = append(toRemove, addr)
		}
	}

	for _, addr := range toRemove {
		session := sm.sessions[addr]
		delete(sm.sessions, addr)
		removed = append(removed, session)
	}
	sm.mu.Unlock()

	for _, session := range removed {
		if session.RemoteConn != nil {
			session.RemoteConn.Close()
		}
		if sm.OnSessionEnd != nil {
			sm.OnSessionEnd(session)
		}
	}

	return len(toRemove)
}

// UpdateActivity updates the last seen timestamp for a session.
func (sm *SessionManager) UpdateActivity(clientAddr string) {
	sm.mu.RLock()
	session, exists := sm.sessions[clientAddr]
	sm.mu.RUnlock()

	if exists {
		session.UpdateLastSeen()
	}
}

// GetAllSessions returns a slice of all active sessions.
// The returned slice is a snapshot and safe to iterate.
func (sm *SessionManager) GetAllSessions() []*Session {
	sm.mu.RLock()
	defer sm.mu.RUnlock()

	sessions := make([]*Session, 0, len(sm.sessions))
	for _, session := range sm.sessions {
		sessions = append(sessions, session)
	}
	return sessions
}

// Count returns the number of active sessions.
func (sm *SessionManager) Count() int {
	sm.mu.RLock()
	defer sm.mu.RUnlock()
	return len(sm.sessions)
}

// SetRemoteConn sets the remote connection for a session.
func (sm *SessionManager) SetRemoteConn(clientAddr string, conn *net.UDPConn) error {
	sm.mu.RLock()
	session, exists := sm.sessions[clientAddr]
	sm.mu.RUnlock()

	if !exists {
		return fmt.Errorf("session not found for client: %s", clientAddr)
	}

	session.mu.Lock()
	session.RemoteConn = conn
	session.mu.Unlock()
	return nil
}

// GarbageCollect removes sessions that have been idle longer than the idle timeout.
// It runs continuously until the context is cancelled.
func (sm *SessionManager) GarbageCollect(ctx context.Context) {
	ticker := time.NewTicker(time.Second * 30) // Check every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sm.cleanupIdleSessions()
		}
	}
}

// GarbageCollectWithCancel is like GarbageCollect but accepts a cancel function for tracking.
func (sm *SessionManager) GarbageCollectWithCancel(ctx context.Context, cancel context.CancelFunc) {
	ticker := time.NewTicker(time.Second * 30) // Check every 30 seconds
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			sm.cleanupIdleSessions()
		}
	}
}

// cleanupIdleSessions removes sessions that have exceeded the idle timeout.
func (sm *SessionManager) cleanupIdleSessions() {
	now := time.Now()
	var toRemove []string

	// First pass: identify sessions to remove (read lock)
	sm.mu.RLock()
	for clientAddr, session := range sm.sessions {
		session.mu.Lock()
		lastSeen := session.LastSeen
		transport := session.Transport
		session.mu.Unlock()

		idleTimeout := sm.getIdleTimeout(session)
		// 中继有自己的媒体计时器与清理 owner，统一 GC 不先删展示记录。
		if transport != "nethernet" && idleTimeout > 0 && now.Sub(lastSeen) > idleTimeout {
			toRemove = append(toRemove, clientAddr)
		}
	}
	sm.mu.RUnlock()

	// Second pass: remove identified sessions
	for _, clientAddr := range toRemove {
		sm.Remove(clientAddr)
	}
}

// GetIdleSessions returns sessions that have been idle longer than the specified duration.
func (sm *SessionManager) GetIdleSessions(idleThreshold time.Duration) []*Session {
	now := time.Now()
	var idleSessions []*Session

	sm.mu.RLock()
	defer sm.mu.RUnlock()

	for _, session := range sm.sessions {
		session.mu.Lock()
		lastSeen := session.LastSeen
		transport := session.Transport
		session.mu.Unlock()

		if transport != "nethernet" && idleThreshold > 0 && now.Sub(lastSeen) > idleThreshold {
			idleSessions = append(idleSessions, session)
		}
	}

	return idleSessions
}

// CleanupNow performs an immediate cleanup of idle sessions.
// Returns the number of sessions removed.
func (sm *SessionManager) CleanupNow() int {
	now := time.Now()
	var toRemove []string

	sm.mu.RLock()
	for clientAddr, session := range sm.sessions {
		session.mu.Lock()
		lastSeen := session.LastSeen
		transport := session.Transport
		session.mu.Unlock()

		idleTimeout := sm.getIdleTimeout(session)
		// 中继有自己的媒体计时器与清理 owner，统一 GC 不先删展示记录。
		if transport != "nethernet" && idleTimeout > 0 && now.Sub(lastSeen) > idleTimeout {
			toRemove = append(toRemove, clientAddr)
		}
	}
	sm.mu.RUnlock()

	for _, clientAddr := range toRemove {
		sm.Remove(clientAddr)
	}

	return len(toRemove)
}
