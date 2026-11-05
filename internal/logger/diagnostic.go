package logger

import (
	"fmt"
	"sync"
	"sync/atomic"
	"time"
)

type diagnosticJob struct {
	message string
	flushed chan struct{}
}

// 断线诊断与普通日志分离：单个后台写入者、有界队列，慢磁盘不能反压转发线程。
// 队列满只保留最新溢出摘要；丢弃数会随下一条摘要报告，不假装日志无损。
type diagnosticWriter struct {
	jobs        chan diagnosticJob
	latest      atomic.Pointer[string]
	overwritten atomic.Uint64
	write       func(string)
}

func newDiagnosticWriter(capacity int, write func(string)) *diagnosticWriter {
	d := &diagnosticWriter{jobs: make(chan diagnosticJob, capacity), write: write}
	go d.run()
	return d
}

func (d *diagnosticWriter) enqueue(message string) {
	select {
	case d.jobs <- diagnosticJob{message: message}:
	default:
		if previous := d.latest.Swap(&message); previous != nil {
			d.overwritten.Add(1)
		}
	}
}

func formatDiagnosticDropped(n uint64) string {
	return fmt.Sprintf("Disconnect diagnostics: overwritten=%d reason=bounded_queue_full latest_snapshot_retained=true", n)
}

func (d *diagnosticWriter) drainLatest() {
	if latest := d.latest.Swap(nil); latest != nil {
		if n := d.overwritten.Swap(0); n > 0 {
			d.write(formatDiagnosticDropped(n))
		}
		d.write(*latest)
	}
}

func (d *diagnosticWriter) run() {
	for job := range d.jobs {
		if job.flushed != nil {
			d.drainLatest()
			close(job.flushed)
			continue
		}
		d.write(job.message)
		// 先保留已入队顺序，积压清空后输出最新溢出快照。
		if len(d.jobs) == 0 {
			d.drainLatest()
		}
	}
}

func (d *diagnosticWriter) flush(timeout time.Duration) bool {
	done := make(chan struct{})
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case d.jobs <- diagnosticJob{flushed: done}:
	case <-timer.C:
		return false
	}
	select {
	case <-done:
		return true
	case <-timer.C:
		return false
	}
}

var diagnosticOnce sync.Once
var diagnostics *diagnosticWriter

func diagnosticSink() *diagnosticWriter {
	diagnosticOnce.Do(func() { diagnostics = newDiagnosticWriter(128, func(message string) { Warn("%s", message) }) })
	return diagnostics
}

// Diagnostic 仅供低频、限长的结束/错误摘要；不得传入数据包或认证内容。
func Diagnostic(message string) {
	// 只有固定字段摘要进入队列；意外超长输入也不能形成无界内存积压。
	if len(message) > 16384 {
		message = message[:16384] + " [truncated]"
	}
	diagnosticSink().enqueue(message)
}

// FlushDiagnostics 在关闭普通日志文件前等待已接收的诊断，超时返回false而不阻塞游戏流量。
func FlushDiagnostics(timeout time.Duration) bool {
	return diagnosticSink().flush(timeout)
}
