package logger

import (
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// 验证摘要写进现有轮转日志，而不是仅被内存队列接收。
func TestDiagnosticWriterWritesExistingLog(t *testing.T) {
	dir := t.TempDir()
	log := NewLogger(io.Discard, LevelInfo, "")
	if err := log.Configure(&LogConfig{LogDir: dir, EnableFileLog: true}); err != nil {
		t.Fatal(err)
	}
	defer log.Close()
	writer := newDiagnosticWriter(2, func(message string) { log.Warn("%s", message) })
	writer.enqueue("RawUDP disconnect_diagnostic fixture-control-EOF")
	if !writer.flush(time.Second) {
		t.Fatal("诊断日志未排空")
	}
	close(writer.jobs)
	files, err := filepath.Glob(filepath.Join(dir, "proxy_*.log"))
	if err != nil || len(files) != 1 {
		t.Fatalf("日志文件缺失: files=%v err=%v", files, err)
	}
	content, err := os.ReadFile(files[0])
	if err != nil || !strings.Contains(string(content), "fixture-control-EOF") {
		t.Fatalf("摘要未写入现有log: %v %s", err, content)
	}
}

func TestDiagnosticWriterBoundedAndNonblocking(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var once sync.Once
	var mu sync.Mutex
	var messages []string
	writer := newDiagnosticWriter(2, func(message string) {
		once.Do(func() { close(entered); <-release })
		mu.Lock()
		messages = append(messages, message)
		mu.Unlock()
	})
	writer.enqueue("first")
	<-entered
	done := make(chan struct{})
	go func() {
		for i := 0; i < 10000; i++ {
			writer.enqueue("overflow")
		}
		writer.enqueue("newest")
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		close(release)
		t.Fatal("慢日志阻塞生产者")
	}
	if len(writer.jobs) != 2 {
		close(release)
		t.Fatal("队列不是固定容量")
	}
	close(release)
	if !writer.flush(time.Second) {
		t.Fatal("无法排空诊断")
	}
	close(writer.jobs)
	mu.Lock()
	defer mu.Unlock()
	foundLatest, foundDrop := false, false
	for _, m := range messages {
		if m == "newest" {
			foundLatest = true
		}
		if strings.Contains(m, "overwritten=") {
			foundDrop = true
		}
	}
	if !foundLatest || !foundDrop {
		t.Fatalf("最新快照或溢出说明丢失: %v", messages)
	}
	if len(messages) > 5 {
		t.Fatalf("溢出错误被逐条写出: %d", len(messages))
	}
}

func TestDiagnosticWriterFlushTimesOutWithoutBlockingProducer(t *testing.T) {
	entered, release := make(chan struct{}), make(chan struct{})
	writer := newDiagnosticWriter(1, func(string) {
		select {
		case <-entered:
		default:
			close(entered)
		}
		<-release
	})
	writer.enqueue("first")
	<-entered
	writer.enqueue("queued")
	if writer.flush(10 * time.Millisecond) {
		close(release)
		t.Fatal("阻塞磁盘下flush应报告超时")
	}
	writer.enqueue("last")
	close(release)
	if !writer.flush(time.Second) {
		t.Fatal("解除阻塞后无法flush")
	}
	close(writer.jobs)
}
