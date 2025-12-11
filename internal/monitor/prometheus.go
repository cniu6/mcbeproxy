// Package monitor provides system monitoring using gopsutil.
package monitor

import (
	"github.com/prometheus/client_golang/prometheus"
)

// PrometheusMetrics holds all Prometheus metrics for the proxy.
type PrometheusMetrics struct {
	// Registry for this instance
	Registry *prometheus.Registry

	// System metrics
	CPUUsage    prometheus.Gauge
	CPUCores    prometheus.Gauge
	MemoryTotal prometheus.Gauge
	MemoryUsed  prometheus.Gauge
	MemoryAvail prometheus.Gauge
	MemoryPct   prometheus.Gauge

	// Process metrics
	ProcessMemory prometheus.Gauge
	ProcessCPU    prometheus.Gauge

	// Go runtime metrics
	Goroutines prometheus.Gauge
	HeapAlloc  prometheus.Gauge
	HeapSys    prometheus.Gauge
	NumGC      prometheus.Gauge

	// Proxy-specific metrics
	ActiveSessions prometheus.Gauge
	TotalBytesUp   prometheus.Counter
	TotalBytesDown prometheus.Counter

	// Monitor reference for updates
	monitor *Monitor
}

// NewPrometheusMetrics creates and registers Prometheus metrics.
func NewPrometheusMetrics(mon *Monitor) *PrometheusMetrics {
	// Create a new registry to avoid conflicts with default registry
	registry := prometheus.NewRegistry()

	pm := &PrometheusMetrics{
		Registry: registry,
		monitor:  mon,
	}

	// System CPU metrics
	pm.CPUUsage = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mcpe_proxy_cpu_usage_percent",
		Help: "Current CPU usage percentage",
	})
	registry.MustRegister(pm.CPUUsage)

	pm.CPUCores = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mcpe_proxy_cpu_cores",
		Help: "Number of CPU cores",
	})
	registry.MustRegister(pm.CPUCores)

	// System memory metrics
	pm.MemoryTotal = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mcpe_proxy_memory_total_bytes",
		Help: "Total system memory in bytes",
	})
	registry.MustRegister(pm.MemoryTotal)

	pm.MemoryUsed = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mcpe_proxy_memory_used_bytes",
		Help: "Used system memory in bytes",
	})
	registry.MustRegister(pm.MemoryUsed)

	pm.MemoryAvail = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mcpe_proxy_memory_available_bytes",
		Help: "Available system memory in bytes",
	})
	registry.MustRegister(pm.MemoryAvail)

	pm.MemoryPct = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mcpe_proxy_memory_used_percent",
		Help: "Memory usage percentage",
	})
	registry.MustRegister(pm.MemoryPct)

	// Process metrics
	pm.ProcessMemory = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mcpe_proxy_process_memory_bytes",
		Help: "Process memory usage in bytes (RSS)",
	})
	registry.MustRegister(pm.ProcessMemory)

	pm.ProcessCPU = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mcpe_proxy_process_cpu_percent",
		Help: "Process CPU usage percentage",
	})
	registry.MustRegister(pm.ProcessCPU)

	// Go runtime metrics
	pm.Goroutines = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mcpe_proxy_goroutines",
		Help: "Number of goroutines",
	})
	registry.MustRegister(pm.Goroutines)

	pm.HeapAlloc = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mcpe_proxy_heap_alloc_bytes",
		Help: "Heap memory allocated in bytes",
	})
	registry.MustRegister(pm.HeapAlloc)

	pm.HeapSys = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mcpe_proxy_heap_sys_bytes",
		Help: "Heap memory obtained from system in bytes",
	})
	registry.MustRegister(pm.HeapSys)

	pm.NumGC = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mcpe_proxy_gc_cycles_total",
		Help: "Total number of GC cycles",
	})
	registry.MustRegister(pm.NumGC)

	// Proxy-specific metrics
	pm.ActiveSessions = prometheus.NewGauge(prometheus.GaugeOpts{
		Name: "mcpe_proxy_active_sessions",
		Help: "Number of active proxy sessions",
	})
	registry.MustRegister(pm.ActiveSessions)

	pm.TotalBytesUp = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "mcpe_proxy_bytes_up_total",
		Help: "Total bytes sent from clients to servers",
	})
	registry.MustRegister(pm.TotalBytesUp)

	pm.TotalBytesDown = prometheus.NewCounter(prometheus.CounterOpts{
		Name: "mcpe_proxy_bytes_down_total",
		Help: "Total bytes sent from servers to clients",
	})
	registry.MustRegister(pm.TotalBytesDown)

	return pm
}

// Update refreshes all metrics with current values.
func (pm *PrometheusMetrics) Update() error {
	if pm.monitor == nil {
		return nil
	}

	// Update CPU metrics
	cpuStats, err := pm.monitor.GetCPUUsage()
	if err == nil {
		pm.CPUUsage.Set(cpuStats.UsagePercent)
		pm.CPUCores.Set(float64(cpuStats.CoreCount))
	}

	// Update memory metrics
	memStats, err := pm.monitor.GetMemoryUsage()
	if err == nil {
		pm.MemoryTotal.Set(float64(memStats.Total))
		pm.MemoryUsed.Set(float64(memStats.Used))
		pm.MemoryAvail.Set(float64(memStats.Available))
		pm.MemoryPct.Set(memStats.UsedPercent)
	}

	// Update process metrics
	procInfo, err := pm.monitor.GetProcessInfo()
	if err == nil {
		pm.ProcessMemory.Set(float64(procInfo.MemoryBytes))
		pm.ProcessCPU.Set(procInfo.CPUPercent)
	}

	// Update Go runtime metrics
	runtimeStats := pm.monitor.GetGoRuntimeStats()
	pm.Goroutines.Set(float64(runtimeStats.GoroutineCount))
	pm.HeapAlloc.Set(float64(runtimeStats.HeapAlloc))
	pm.HeapSys.Set(float64(runtimeStats.HeapSys))
	pm.NumGC.Set(float64(runtimeStats.NumGC))

	return nil
}

// SetActiveSessions updates the active sessions metric.
func (pm *PrometheusMetrics) SetActiveSessions(count int) {
	pm.ActiveSessions.Set(float64(count))
}

// AddBytesUp adds to the bytes up counter.
func (pm *PrometheusMetrics) AddBytesUp(bytes int64) {
	pm.TotalBytesUp.Add(float64(bytes))
}

// AddBytesDown adds to the bytes down counter.
func (pm *PrometheusMetrics) AddBytesDown(bytes int64) {
	pm.TotalBytesDown.Add(float64(bytes))
}
