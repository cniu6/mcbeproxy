// Package monitor provides system monitoring functionality.
package monitor

import (
	"fmt"
	"runtime"
	"runtime/pprof"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// GoroutineInfo represents information about a tracked goroutine.
type GoroutineInfo struct {
	ID           int64     `json:"id"`
	Name         string    `json:"name"`
	StartTime    time.Time `json:"start_time"`
	Duration     string    `json:"duration"`
	Stack        string    `json:"stack,omitempty"`
	State        string    `json:"state"`
	Component    string    `json:"component"` // e.g., "proxy", "api", "session"
	Description  string    `json:"description,omitempty"`
	IsBackground bool      `json:"is_background"` // Background tasks are expected to run long
}

// GoroutineStats represents overall goroutine statistics.
type GoroutineStats struct {
	TotalCount     int                    `json:"total_count"`
	TrackedCount   int                    `json:"tracked_count"`
	ByComponent    map[string]int         `json:"by_component"`
	ByState        map[string]int         `json:"by_state"`
	LongRunning    []*GoroutineInfo       `json:"long_running,omitempty"`    // Running > 1 minute
	PotentialLeaks []*GoroutineInfo       `json:"potential_leaks,omitempty"` // Running > 5 minutes with no activity
	RuntimeStacks  []RuntimeGoroutineInfo `json:"runtime_stacks,omitempty"`
}

// RuntimeGoroutineInfo represents a goroutine from runtime stack.
type RuntimeGoroutineInfo struct {
	ID       int64  `json:"id"`
	State    string `json:"state"`
	WaitTime string `json:"wait_time,omitempty"`
	Stack    string `json:"stack"`
	Function string `json:"function"`
}

// GoroutineManager tracks and manages goroutines for debugging and leak detection.
type GoroutineManager struct {
	mu         sync.RWMutex
	goroutines map[int64]*trackedGoroutine
	nextID     atomic.Int64
	enabled    atomic.Bool
}

type trackedGoroutine struct {
	info         GoroutineInfo
	cancelFunc   func() // Optional cancel function
	lastActive   time.Time
	isBackground bool // Background tasks are expected to run long
}

var (
	globalManager     *GoroutineManager
	globalManagerOnce sync.Once
)

// GetGoroutineManager returns the global goroutine manager instance.
func GetGoroutineManager() *GoroutineManager {
	globalManagerOnce.Do(func() {
		globalManager = &GoroutineManager{
			goroutines: make(map[int64]*trackedGoroutine),
		}
		globalManager.enabled.Store(true)
	})
	return globalManager
}

// Track registers a new goroutine for tracking.
// Returns an ID that should be used to untrack when the goroutine exits.
func (gm *GoroutineManager) Track(name, component, description string, cancelFunc func()) int64 {
	return gm.TrackWithOptions(name, component, description, cancelFunc, false)
}

// TrackBackground registers a background goroutine that is expected to run for the lifetime of the application.
// Background goroutines are not flagged as potential leaks.
func (gm *GoroutineManager) TrackBackground(name, component, description string, cancelFunc func()) int64 {
	return gm.TrackWithOptions(name, component, description, cancelFunc, true)
}

// TrackWithOptions registers a goroutine with full options.
func (gm *GoroutineManager) TrackWithOptions(name, component, description string, cancelFunc func(), isBackground bool) int64 {
	if !gm.enabled.Load() {
		return 0
	}

	id := gm.nextID.Add(1)
	now := time.Now()

	gm.mu.Lock()
	defer gm.mu.Unlock()

	gm.goroutines[id] = &trackedGoroutine{
		info: GoroutineInfo{
			ID:           id,
			Name:         name,
			StartTime:    now,
			State:        "running",
			Component:    component,
			Description:  description,
			IsBackground: isBackground,
		},
		cancelFunc:   cancelFunc,
		lastActive:   now,
		isBackground: isBackground,
	}

	return id
}

// Untrack removes a goroutine from tracking.
func (gm *GoroutineManager) Untrack(id int64) {
	if id == 0 {
		return
	}

	gm.mu.Lock()
	defer gm.mu.Unlock()
	delete(gm.goroutines, id)
}

// UpdateActivity updates the last active time for a tracked goroutine.
func (gm *GoroutineManager) UpdateActivity(id int64) {
	if id == 0 {
		return
	}

	gm.mu.Lock()
	defer gm.mu.Unlock()

	if g, ok := gm.goroutines[id]; ok {
		g.lastActive = time.Now()
	}
}

// SetState updates the state of a tracked goroutine.
func (gm *GoroutineManager) SetState(id int64, state string) {
	if id == 0 {
		return
	}

	gm.mu.Lock()
	defer gm.mu.Unlock()

	if g, ok := gm.goroutines[id]; ok {
		g.info.State = state
		g.lastActive = time.Now()
	}
}

// Cancel attempts to cancel a tracked goroutine.
func (gm *GoroutineManager) Cancel(id int64) bool {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	if g, ok := gm.goroutines[id]; ok && g.cancelFunc != nil {
		g.cancelFunc()
		g.info.State = "cancelled"
		return true
	}
	return false
}

// GetStats returns comprehensive goroutine statistics.
func (gm *GoroutineManager) GetStats(includeStacks bool) *GoroutineStats {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	now := time.Now()
	stats := &GoroutineStats{
		TotalCount:   runtime.NumGoroutine(),
		TrackedCount: len(gm.goroutines),
		ByComponent:  make(map[string]int),
		ByState:      make(map[string]int),
	}

	for _, g := range gm.goroutines {
		stats.ByComponent[g.info.Component]++
		stats.ByState[g.info.State]++

		duration := now.Sub(g.info.StartTime)
		info := &GoroutineInfo{
			ID:           g.info.ID,
			Name:         g.info.Name,
			StartTime:    g.info.StartTime,
			Duration:     duration.String(),
			State:        g.info.State,
			Component:    g.info.Component,
			Description:  g.info.Description,
			IsBackground: g.isBackground,
		}

		// Long running: > 1 minute (but not background tasks)
		if duration > time.Minute && !g.isBackground {
			stats.LongRunning = append(stats.LongRunning, info)
		}

		// Potential leak: > 5 minutes with no activity in last 2 minutes
		// Background tasks are excluded from leak detection
		inactiveTime := now.Sub(g.lastActive)
		if !g.isBackground && duration > 5*time.Minute && inactiveTime > 2*time.Minute {
			info.Description = fmt.Sprintf("%s (inactive for %s)", info.Description, inactiveTime.Round(time.Second))
			stats.PotentialLeaks = append(stats.PotentialLeaks, info)
		}
	}

	// Sort by duration (longest first)
	sort.Slice(stats.LongRunning, func(i, j int) bool {
		return stats.LongRunning[i].StartTime.Before(stats.LongRunning[j].StartTime)
	})
	sort.Slice(stats.PotentialLeaks, func(i, j int) bool {
		return stats.PotentialLeaks[i].StartTime.Before(stats.PotentialLeaks[j].StartTime)
	})

	// Include runtime stacks if requested
	if includeStacks {
		stats.RuntimeStacks = gm.getRuntimeStacks()
	}

	return stats
}

// getRuntimeStacks parses runtime goroutine stacks.
func (gm *GoroutineManager) getRuntimeStacks() []RuntimeGoroutineInfo {
	// Get all goroutine stacks
	buf := make([]byte, 1024*1024) // 1MB buffer
	n := runtime.Stack(buf, true)
	stackStr := string(buf[:n])

	var stacks []RuntimeGoroutineInfo
	goroutineBlocks := strings.Split(stackStr, "\n\n")

	for _, block := range goroutineBlocks {
		if block == "" {
			continue
		}

		lines := strings.Split(block, "\n")
		if len(lines) < 1 {
			continue
		}

		// Parse header line: "goroutine 1 [running]:" or "goroutine 1 [chan receive, 5 minutes]:"
		header := lines[0]
		info := RuntimeGoroutineInfo{
			Stack: block,
		}

		// Extract goroutine ID
		var id int64
		var state string
		if _, err := fmt.Sscanf(header, "goroutine %d [%s", &id, &state); err == nil {
			info.ID = id
			// Clean up state (remove trailing ]:)
			state = strings.TrimSuffix(state, "]:")
			state = strings.TrimSuffix(state, ",")

			// Check for wait time
			if idx := strings.Index(header, ","); idx > 0 {
				endIdx := strings.Index(header[idx:], "]")
				if endIdx > 0 {
					info.WaitTime = strings.TrimSpace(header[idx+1 : idx+endIdx])
				}
			}
			info.State = state
		}

		// Extract main function name
		if len(lines) > 1 {
			funcLine := lines[1]
			if idx := strings.Index(funcLine, "("); idx > 0 {
				info.Function = strings.TrimSpace(funcLine[:idx])
			} else {
				info.Function = strings.TrimSpace(funcLine)
			}
		}

		stacks = append(stacks, info)
	}

	return stacks
}

// GetTrackedGoroutines returns all tracked goroutines.
func (gm *GoroutineManager) GetTrackedGoroutines() []*GoroutineInfo {
	gm.mu.RLock()
	defer gm.mu.RUnlock()

	now := time.Now()
	result := make([]*GoroutineInfo, 0, len(gm.goroutines))

	for _, g := range gm.goroutines {
		info := &GoroutineInfo{
			ID:          g.info.ID,
			Name:        g.info.Name,
			StartTime:   g.info.StartTime,
			Duration:    now.Sub(g.info.StartTime).String(),
			State:       g.info.State,
			Component:   g.info.Component,
			Description: g.info.Description,
		}
		result = append(result, info)
	}

	// Sort by start time
	sort.Slice(result, func(i, j int) bool {
		return result[i].StartTime.Before(result[j].StartTime)
	})

	return result
}

// GetPprofGoroutines returns goroutine profile data.
func (gm *GoroutineManager) GetPprofGoroutines() string {
	var buf strings.Builder
	profile := pprof.Lookup("goroutine")
	if profile != nil {
		profile.WriteTo(&buf, 2) // debug=2 for full stacks
	}
	return buf.String()
}

// CancelAll attempts to cancel all tracked goroutines.
func (gm *GoroutineManager) CancelAll() int {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	cancelled := 0
	for _, g := range gm.goroutines {
		if g.cancelFunc != nil {
			g.cancelFunc()
			g.info.State = "cancelled"
			cancelled++
		}
	}
	return cancelled
}

// CancelByComponent cancels all goroutines of a specific component.
func (gm *GoroutineManager) CancelByComponent(component string) int {
	gm.mu.Lock()
	defer gm.mu.Unlock()

	cancelled := 0
	for _, g := range gm.goroutines {
		if g.info.Component == component && g.cancelFunc != nil {
			g.cancelFunc()
			g.info.State = "cancelled"
			cancelled++
		}
	}
	return cancelled
}

// Enable enables goroutine tracking.
func (gm *GoroutineManager) Enable() {
	gm.enabled.Store(true)
}

// Disable disables goroutine tracking.
func (gm *GoroutineManager) Disable() {
	gm.enabled.Store(false)
}

// IsEnabled returns whether tracking is enabled.
func (gm *GoroutineManager) IsEnabled() bool {
	return gm.enabled.Load()
}

// Clear removes all tracked goroutines.
func (gm *GoroutineManager) Clear() {
	gm.mu.Lock()
	defer gm.mu.Unlock()
	gm.goroutines = make(map[int64]*trackedGoroutine)
}
