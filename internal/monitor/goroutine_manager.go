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
	// Enhanced memory stats
	MemStats *GoMemoryStats `json:"mem_stats,omitempty"`
	// Goroutine state summary from runtime
	RuntimeStateSummary map[string]int `json:"runtime_state_summary,omitempty"`
}

// GoMemoryStats provides detailed Go runtime memory statistics.
type GoMemoryStats struct {
	// General stats
	Alloc       uint64 `json:"alloc"`        // Bytes allocated and still in use
	TotalAlloc  uint64 `json:"total_alloc"`  // Bytes allocated (even if freed)
	Sys         uint64 `json:"sys"`          // Bytes obtained from system
	Mallocs     uint64 `json:"mallocs"`      // Number of mallocs
	Frees       uint64 `json:"frees"`        // Number of frees
	LiveObjects uint64 `json:"live_objects"` // Mallocs - Frees

	// Heap stats
	HeapAlloc    uint64 `json:"heap_alloc"`    // Bytes allocated and still in use
	HeapSys      uint64 `json:"heap_sys"`      // Bytes obtained from system for heap
	HeapIdle     uint64 `json:"heap_idle"`     // Bytes in idle spans
	HeapInuse    uint64 `json:"heap_inuse"`    // Bytes in non-idle spans
	HeapReleased uint64 `json:"heap_released"` // Bytes released to OS
	HeapObjects  uint64 `json:"heap_objects"`  // Number of allocated objects

	// Stack stats
	StackInuse uint64 `json:"stack_inuse"` // Bytes used by stack allocator
	StackSys   uint64 `json:"stack_sys"`   // Bytes obtained from system for stack

	// Off-heap stats
	MSpanInuse  uint64 `json:"mspan_inuse"`  // Bytes used by mspan structures
	MSpanSys    uint64 `json:"mspan_sys"`    // Bytes obtained from system for mspan
	MCacheInuse uint64 `json:"mcache_inuse"` // Bytes used by mcache structures
	MCacheSys   uint64 `json:"mcache_sys"`   // Bytes obtained from system for mcache
	BuckHashSys uint64 `json:"buckhash_sys"` // Bytes used by profiling bucket hash table
	GCSys       uint64 `json:"gc_sys"`       // Bytes used by GC metadata
	OtherSys    uint64 `json:"other_sys"`    // Bytes used by other system allocations

	// GC stats
	NextGC        uint64  `json:"next_gc"`         // Target heap size for next GC
	LastGC        uint64  `json:"last_gc"`         // Time of last GC (nanoseconds since epoch)
	NumGC         uint32  `json:"num_gc"`          // Number of completed GC cycles
	NumForcedGC   uint32  `json:"num_forced_gc"`   // Number of forced GC cycles
	GCCPUFraction float64 `json:"gc_cpu_fraction"` // Fraction of CPU time used by GC

	// Pause stats
	PauseTotalNs uint64 `json:"pause_total_ns"` // Total GC pause time
	LastPauseNs  uint64 `json:"last_pause_ns"`  // Last GC pause duration
}

// RuntimeGoroutineInfo represents a goroutine from runtime stack.
type RuntimeGoroutineInfo struct {
	ID             int64  `json:"id"`
	State          string `json:"state"`
	WaitTime       string `json:"wait_time,omitempty"`
	Stack          string `json:"stack"`
	Function       string `json:"function"`
	LockedToThread bool   `json:"locked_to_thread,omitempty"`
	CreatedBy      string `json:"created_by,omitempty"`
	StackLines     int    `json:"stack_lines"`
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
// The goroutine will be automatically removed after a short delay to allow cleanup.
func (gm *GoroutineManager) Cancel(id int64) bool {
	gm.mu.Lock()
	g, ok := gm.goroutines[id]
	if !ok || g.cancelFunc == nil {
		gm.mu.Unlock()
		return false
	}
	g.cancelFunc()
	g.info.State = "cancelled"
	gm.mu.Unlock()

	// Schedule automatic cleanup after 5 seconds
	// This gives the goroutine time to exit gracefully via defer Untrack
	go func() {
		time.Sleep(5 * time.Second)
		gm.mu.Lock()
		defer gm.mu.Unlock()
		// Only remove if still in cancelled state (not re-tracked)
		if g, exists := gm.goroutines[id]; exists && g.info.State == "cancelled" {
			delete(gm.goroutines, id)
		}
	}()

	return true
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

	// Always include memory stats for debugging
	stats.MemStats = gm.getMemoryStats()

	// Include runtime stacks if requested
	if includeStacks {
		stats.RuntimeStacks, stats.RuntimeStateSummary = gm.getRuntimeStacksWithSummary()
	}

	return stats
}

// getMemoryStats returns detailed memory statistics.
func (gm *GoroutineManager) getMemoryStats() *GoMemoryStats {
	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	return &GoMemoryStats{
		// General stats
		Alloc:       m.Alloc,
		TotalAlloc:  m.TotalAlloc,
		Sys:         m.Sys,
		Mallocs:     m.Mallocs,
		Frees:       m.Frees,
		LiveObjects: m.Mallocs - m.Frees,

		// Heap stats
		HeapAlloc:    m.HeapAlloc,
		HeapSys:      m.HeapSys,
		HeapIdle:     m.HeapIdle,
		HeapInuse:    m.HeapInuse,
		HeapReleased: m.HeapReleased,
		HeapObjects:  m.HeapObjects,

		// Stack stats
		StackInuse: m.StackInuse,
		StackSys:   m.StackSys,

		// Off-heap stats
		MSpanInuse:  m.MSpanInuse,
		MSpanSys:    m.MSpanSys,
		MCacheInuse: m.MCacheInuse,
		MCacheSys:   m.MCacheSys,
		BuckHashSys: m.BuckHashSys,
		GCSys:       m.GCSys,
		OtherSys:    m.OtherSys,

		// GC stats
		NextGC:        m.NextGC,
		LastGC:        m.LastGC,
		NumGC:         m.NumGC,
		NumForcedGC:   m.NumForcedGC,
		GCCPUFraction: m.GCCPUFraction,

		// Pause stats
		PauseTotalNs: m.PauseTotalNs,
		LastPauseNs:  m.PauseNs[(m.NumGC+255)%256],
	}
}

// getRuntimeStacksWithSummary parses runtime goroutine stacks and returns state summary.
func (gm *GoroutineManager) getRuntimeStacksWithSummary() ([]RuntimeGoroutineInfo, map[string]int) {
	stacks := gm.getRuntimeStacks()
	summary := make(map[string]int)

	for _, s := range stacks {
		// Normalize state for summary
		state := s.State
		if strings.Contains(state, "wait") || strings.Contains(state, "select") {
			state = "waiting"
		} else if strings.Contains(state, "chan") {
			state = "chan_blocked"
		} else if strings.Contains(state, "syscall") || strings.Contains(state, "IO") {
			state = "syscall/IO"
		} else if strings.Contains(state, "sleep") {
			state = "sleeping"
		} else if strings.Contains(state, "semacquire") {
			state = "mutex_blocked"
		}
		summary[state]++
	}

	return stacks, summary
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
			Stack:      block,
			StackLines: len(lines),
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

			// Check if locked to thread
			if strings.Contains(header, "locked to thread") {
				info.LockedToThread = true
			}
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

		// Extract created by info (last lines often contain "created by ...")
		for i := len(lines) - 1; i >= 0; i-- {
			if strings.Contains(lines[i], "created by ") {
				info.CreatedBy = strings.TrimSpace(strings.TrimPrefix(lines[i], "created by "))
				break
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
	cancelledIDs := make([]int64, 0)
	for id, g := range gm.goroutines {
		if g.cancelFunc != nil {
			g.cancelFunc()
			g.info.State = "cancelled"
			cancelledIDs = append(cancelledIDs, id)
		}
	}
	gm.mu.Unlock()

	// Schedule automatic cleanup
	if len(cancelledIDs) > 0 {
		go func() {
			time.Sleep(5 * time.Second)
			gm.mu.Lock()
			defer gm.mu.Unlock()
			for _, id := range cancelledIDs {
				if g, exists := gm.goroutines[id]; exists && g.info.State == "cancelled" {
					delete(gm.goroutines, id)
				}
			}
		}()
	}

	return len(cancelledIDs)
}

// CancelByComponent cancels all goroutines of a specific component.
func (gm *GoroutineManager) CancelByComponent(component string) int {
	gm.mu.Lock()
	cancelledIDs := make([]int64, 0)
	for id, g := range gm.goroutines {
		if g.info.Component == component && g.cancelFunc != nil {
			g.cancelFunc()
			g.info.State = "cancelled"
			cancelledIDs = append(cancelledIDs, id)
		}
	}
	gm.mu.Unlock()

	// Schedule automatic cleanup
	if len(cancelledIDs) > 0 {
		go func() {
			time.Sleep(5 * time.Second)
			gm.mu.Lock()
			defer gm.mu.Unlock()
			for _, id := range cancelledIDs {
				if g, exists := gm.goroutines[id]; exists && g.info.State == "cancelled" {
					delete(gm.goroutines, id)
				}
			}
		}()
	}

	return len(cancelledIDs)
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
