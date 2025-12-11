// Package proxy provides the core UDP proxy functionality.
package proxy

import (
	"sync"
)

// DefaultBufferSize is the default size for UDP packet buffers.
// MCBE packets can be up to 1400 bytes typically, but we use a larger buffer
// to handle potential fragmentation and larger packets.
const DefaultBufferSize = 2048

// MaxBufferSize is the maximum allowed buffer size.
const MaxBufferSize = 65535

// AutoBufferSize indicates automatic buffer sizing based on received packets.
const AutoBufferSize = -1

// BufferPool provides a pool of reusable byte buffers to minimize memory allocations
// during packet forwarding operations.
type BufferPool struct {
	pool     *sync.Pool
	size     int
	autoMode bool
}

// NewBufferPool creates a new buffer pool with the specified buffer size.
// If size is -1 (AutoBufferSize), uses auto mode with default initial size.
func NewBufferPool(size int) *BufferPool {
	autoMode := size == AutoBufferSize
	if size <= 0 {
		size = DefaultBufferSize
	}
	if size > MaxBufferSize {
		size = MaxBufferSize
	}
	return &BufferPool{
		pool: &sync.Pool{
			New: func() interface{} {
				buf := make([]byte, size)
				return &buf
			},
		},
		size:     size,
		autoMode: autoMode,
	}
}

// Get retrieves a buffer from the pool.
// The returned buffer should be returned to the pool after use via Put.
func (bp *BufferPool) Get() *[]byte {
	return bp.pool.Get().(*[]byte)
}

// GetWithSize retrieves a buffer with at least the specified size.
// Used in auto mode to handle varying packet sizes.
func (bp *BufferPool) GetWithSize(minSize int) *[]byte {
	buf := bp.pool.Get().(*[]byte)
	if len(*buf) < minSize {
		// Need a larger buffer
		newBuf := make([]byte, minSize)
		return &newBuf
	}
	return buf
}

// Put returns a buffer to the pool for reuse.
// The buffer will be reset to its original capacity.
func (bp *BufferPool) Put(buf *[]byte) {
	if buf == nil {
		return
	}
	// Only return buffers of the expected size to the pool
	if cap(*buf) == bp.size {
		*buf = (*buf)[:bp.size]
		bp.pool.Put(buf)
	}
	// Larger buffers are discarded and will be GC'd
}

// Size returns the buffer size used by this pool.
func (bp *BufferPool) Size() int {
	return bp.size
}

// IsAutoMode returns true if the pool is in auto-sizing mode.
func (bp *BufferPool) IsAutoMode() bool {
	return bp.autoMode
}
