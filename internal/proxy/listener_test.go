package proxy

import "testing"

func TestDefaultUDPListenerWorkerCountRange(t *testing.T) {
	workers := defaultUDPListenerWorkerCount()
	if workers < 32 || workers > 128 {
		t.Fatalf("defaultUDPListenerWorkerCount out of expected range: %d", workers)
	}
}

func TestDefaultUDPListenerQueueSizeTracksWorkers(t *testing.T) {
	workers := defaultUDPListenerWorkerCount()
	queueSize := defaultUDPListenerQueueSize()
	if queueSize != workers*4 {
		t.Fatalf("defaultUDPListenerQueueSize=%d, want %d", queueSize, workers*4)
	}
}
