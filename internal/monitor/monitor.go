// Package monitor provides system monitoring using gopsutil.
package monitor

import (
	"os"
	"runtime"
	"sync"
	"time"

	"github.com/shirou/gopsutil/v3/cpu"
	"github.com/shirou/gopsutil/v3/disk"
	"github.com/shirou/gopsutil/v3/mem"
	gopsnet "github.com/shirou/gopsutil/v3/net"
	"github.com/shirou/gopsutil/v3/process"
)

// Monitor provides system monitoring functionality using gopsutil.
type Monitor struct {
	startTime      time.Time
	lastNetStats   map[string]netSnapshot
	lastNetStatsAt time.Time
	lastNetStatsMu sync.Mutex
}

type netSnapshot struct {
	bytesSent uint64
	bytesRecv uint64
}

// NewMonitor creates a new Monitor instance.
func NewMonitor() *Monitor {
	return &Monitor{
		startTime:    time.Now(),
		lastNetStats: make(map[string]netSnapshot),
	}
}

// CPUStats represents CPU usage statistics.
type CPUStats struct {
	UsagePercent float64 `json:"usage_percent"`
	CoreCount    int     `json:"core_count"`
}

// MemoryStats represents memory usage statistics.
type MemoryStats struct {
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Available   uint64  `json:"available"`
	UsedPercent float64 `json:"used_percent"`
	SwapTotal   uint64  `json:"swap_total"`
	SwapUsed    uint64  `json:"swap_used"`
	SwapFree    uint64  `json:"swap_free"`
	SwapPercent float64 `json:"swap_percent"`
}

// DiskStats represents disk usage statistics for a partition.
type DiskStats struct {
	Path        string  `json:"path"`
	Total       uint64  `json:"total"`
	Used        uint64  `json:"used"`
	Free        uint64  `json:"free"`
	UsedPercent float64 `json:"used_percent"`
}

// NetworkStats represents network interface statistics.
type NetworkStats struct {
	Name        string  `json:"name"`
	BytesSent   uint64  `json:"bytes_sent"`
	BytesRecv   uint64  `json:"bytes_recv"`
	PacketsSent uint64  `json:"packets_sent"`
	PacketsRecv uint64  `json:"packets_recv"`
	SpeedIn     float64 `json:"speed_in_bps"`  // Bytes per second (calculated)
	SpeedOut    float64 `json:"speed_out_bps"` // Bytes per second (calculated)
}

// ProcessInfo represents current process information.
type ProcessInfo struct {
	PID         int32   `json:"pid"`
	MemoryBytes uint64  `json:"memory_bytes"`
	CPUPercent  float64 `json:"cpu_percent"`
}

// RuntimeStats represents Go runtime statistics.
type RuntimeStats struct {
	GoroutineCount int    `json:"goroutine_count"`
	HeapAlloc      uint64 `json:"heap_alloc"`
	HeapSys        uint64 `json:"heap_sys"`
	HeapInuse      uint64 `json:"heap_inuse"`
	StackInuse     uint64 `json:"stack_inuse"`
	NumGC          uint32 `json:"num_gc"`
}

// SystemStats represents all system statistics.
type SystemStats struct {
	CPU          CPUStats       `json:"cpu"`
	Memory       MemoryStats    `json:"memory"`
	Disk         []DiskStats    `json:"disk"`
	Network      []NetworkStats `json:"network"`
	NetworkTotal NetworkTotal   `json:"network_total"`
	Process      ProcessInfo    `json:"process"`
	GoRuntime    RuntimeStats   `json:"go_runtime"`
	Uptime       int64          `json:"uptime_seconds"`
	StartTime    string         `json:"start_time"` // ISO 8601 format
}

// NetworkTotal represents total network statistics across all interfaces.
type NetworkTotal struct {
	BytesSent   uint64  `json:"bytes_sent"`
	BytesRecv   uint64  `json:"bytes_recv"`
	SpeedIn     float64 `json:"speed_in_bps"`
	SpeedOut    float64 `json:"speed_out_bps"`
	PacketsSent uint64  `json:"packets_sent"`
	PacketsRecv uint64  `json:"packets_recv"`
}

// GetCPUUsage returns CPU usage percentage and core count.
// Requirements: 6.1
func (m *Monitor) GetCPUUsage() (*CPUStats, error) {
	// Get CPU usage percentage (average over 100ms)
	percentages, err := cpu.Percent(100*time.Millisecond, false)
	if err != nil {
		return nil, err
	}

	usagePercent := 0.0
	if len(percentages) > 0 {
		usagePercent = percentages[0]
	}

	// Get core count
	coreCount, err := cpu.Counts(true)
	if err != nil {
		return nil, err
	}

	return &CPUStats{
		UsagePercent: usagePercent,
		CoreCount:    coreCount,
	}, nil
}

// GetMemoryUsage returns memory usage statistics.
// Requirements: 6.2
func (m *Monitor) GetMemoryUsage() (*MemoryStats, error) {
	vmStat, err := mem.VirtualMemory()
	if err != nil {
		return nil, err
	}

	swapStat, err := mem.SwapMemory()
	if err != nil {
		// Swap might not be available, use zero values
		swapStat = &mem.SwapMemoryStat{}
	}

	return &MemoryStats{
		Total:       vmStat.Total,
		Used:        vmStat.Used,
		Available:   vmStat.Available,
		UsedPercent: vmStat.UsedPercent,
		SwapTotal:   swapStat.Total,
		SwapUsed:    swapStat.Used,
		SwapFree:    swapStat.Free,
		SwapPercent: swapStat.UsedPercent,
	}, nil
}

// GetDiskUsage returns disk usage for all mounted partitions.
// Requirements: 6.3
func (m *Monitor) GetDiskUsage() ([]DiskStats, error) {
	partitions, err := disk.Partitions(false)
	if err != nil {
		return nil, err
	}

	var stats []DiskStats
	for _, partition := range partitions {
		usage, err := disk.Usage(partition.Mountpoint)
		if err != nil {
			// Skip partitions we can't read
			continue
		}

		stats = append(stats, DiskStats{
			Path:        partition.Mountpoint,
			Total:       usage.Total,
			Used:        usage.Used,
			Free:        usage.Free,
			UsedPercent: usage.UsedPercent,
		})
	}

	return stats, nil
}

// GetNetworkStats returns network interface statistics with speed calculation.
// Requirements: 6.4
func (m *Monitor) GetNetworkStats() ([]NetworkStats, error) {
	ioCounters, err := gopsnet.IOCounters(true)
	if err != nil {
		return nil, err
	}

	m.lastNetStatsMu.Lock()
	defer m.lastNetStatsMu.Unlock()

	now := time.Now()
	elapsed := now.Sub(m.lastNetStatsAt).Seconds()
	if elapsed <= 0 {
		elapsed = 1
	}

	var stats []NetworkStats
	for _, counter := range ioCounters {
		stat := NetworkStats{
			Name:        counter.Name,
			BytesSent:   counter.BytesSent,
			BytesRecv:   counter.BytesRecv,
			PacketsSent: counter.PacketsSent,
			PacketsRecv: counter.PacketsRecv,
		}

		// Calculate speed if we have previous data
		if last, ok := m.lastNetStats[counter.Name]; ok && elapsed > 0 {
			stat.SpeedIn = float64(counter.BytesRecv-last.bytesRecv) / elapsed
			stat.SpeedOut = float64(counter.BytesSent-last.bytesSent) / elapsed
		}

		stats = append(stats, stat)
	}

	// Update last stats
	for _, counter := range ioCounters {
		m.lastNetStats[counter.Name] = netSnapshot{
			bytesSent: counter.BytesSent,
			bytesRecv: counter.BytesRecv,
		}
	}
	m.lastNetStatsAt = now

	return stats, nil
}

// GetProcessInfo returns current process information.
// Requirements: 6.5
func (m *Monitor) GetProcessInfo() (*ProcessInfo, error) {
	pid := int32(os.Getpid())
	proc, err := process.NewProcess(pid)
	if err != nil {
		return nil, err
	}

	memInfo, err := proc.MemoryInfo()
	if err != nil {
		return nil, err
	}

	cpuPercent, err := proc.CPUPercent()
	if err != nil {
		// CPU percent might fail on first call, use 0
		cpuPercent = 0
	}

	return &ProcessInfo{
		PID:         pid,
		MemoryBytes: memInfo.RSS,
		CPUPercent:  cpuPercent,
	}, nil
}

// GetGoRuntimeStats returns Go runtime statistics.
// Requirements: 6.6
func (m *Monitor) GetGoRuntimeStats() *RuntimeStats {
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	return &RuntimeStats{
		GoroutineCount: runtime.NumGoroutine(),
		HeapAlloc:      memStats.HeapAlloc,
		HeapSys:        memStats.HeapSys,
		HeapInuse:      memStats.HeapInuse,
		StackInuse:     memStats.StackInuse,
		NumGC:          memStats.NumGC,
	}
}

// GetSystemStats returns all system statistics.
// Requirements: 6.1, 6.2, 6.3, 6.4, 6.5, 6.6
func (m *Monitor) GetSystemStats() (*SystemStats, error) {
	cpuStats, err := m.GetCPUUsage()
	if err != nil {
		return nil, err
	}

	memStats, err := m.GetMemoryUsage()
	if err != nil {
		return nil, err
	}

	diskStats, err := m.GetDiskUsage()
	if err != nil {
		return nil, err
	}

	netStats, err := m.GetNetworkStats()
	if err != nil {
		return nil, err
	}

	procInfo, err := m.GetProcessInfo()
	if err != nil {
		return nil, err
	}

	runtimeStats := m.GetGoRuntimeStats()

	// Calculate network totals
	var netTotal NetworkTotal
	for _, ns := range netStats {
		netTotal.BytesSent += ns.BytesSent
		netTotal.BytesRecv += ns.BytesRecv
		netTotal.PacketsSent += ns.PacketsSent
		netTotal.PacketsRecv += ns.PacketsRecv
		netTotal.SpeedIn += ns.SpeedIn
		netTotal.SpeedOut += ns.SpeedOut
	}

	return &SystemStats{
		CPU:          *cpuStats,
		Memory:       *memStats,
		Disk:         diskStats,
		Network:      netStats,
		NetworkTotal: netTotal,
		Process:      *procInfo,
		GoRuntime:    *runtimeStats,
		Uptime:       int64(time.Since(m.startTime).Seconds()),
		StartTime:    m.startTime.Format(time.RFC3339),
	}, nil
}
