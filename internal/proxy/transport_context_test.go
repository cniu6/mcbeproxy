package proxy

import (
	"context"
	"testing"
)

func TestPersistentTransportContextDetachesCancellation(t *testing.T) {
	parent, cancel := context.WithCancel(context.Background())
	child := persistentTransportContext(parent)
	cancel()
	if err := child.Err(); err != nil {
		t.Fatalf("persistent transport context should survive parent cancellation, got %v", err)
	}
}
