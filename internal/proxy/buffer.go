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

// Global buffer pools for different sizes to reduce GC pressure
// Note: sync.Pool items are cleared on every GC cycle, so these pools
// help reduce allocations but don't cause memory leaks.
var (
	// SmallBufferPool for small packets (2KB) - ping/pong, small control packets
	SmallBufferPool = &sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 2048)
			return &buf
		},
	}

	// MediumBufferPool for medium packets (8KB) - typical game packets
	MediumBufferPool = &sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 8192)
			return &buf
		},
	}

	// LargeBufferPool for large packets (32KB) - reduced from 64KB to save memory
	LargeBufferPool = &sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 32768)
			return &buf
		},
	}

	// RakNetBufferPool for RakNet packets (32KB) - reduced from 64KB to save memory
	RakNetBufferPool = &sync.Pool{
		New: func() interface{} {
			buf := make([]byte, 32768)
			return &buf
		},
	}
)

// GetSmallBuffer gets a 2KB buffer from the pool
func GetSmallBuffer() *[]byte {
	return SmallBufferPool.Get().(*[]byte)
}

// PutSmallBuffer returns a 2KB buffer to the pool
func PutSmallBuffer(buf *[]byte) {
	if buf != nil && cap(*buf) >= 2048 {
		*buf = (*buf)[:2048]
		SmallBufferPool.Put(buf)
	}
}

// GetMediumBuffer gets an 8KB buffer from the pool
func GetMediumBuffer() *[]byte {
	return MediumBufferPool.Get().(*[]byte)
}

// PutMediumBuffer returns an 8KB buffer to the pool
func PutMediumBuffer(buf *[]byte) {
	if buf != nil && cap(*buf) >= 8192 {
		*buf = (*buf)[:8192]
		MediumBufferPool.Put(buf)
	}
}

// GetLargeBuffer gets a 64KB buffer from the pool
func GetLargeBuffer() *[]byte {
	return LargeBufferPool.Get().(*[]byte)
}

// PutLargeBuffer returns a 32KB buffer to the pool
func PutLargeBuffer(buf *[]byte) {
	if buf != nil && cap(*buf) >= 32768 {
		*buf = (*buf)[:32768]
		LargeBufferPool.Put(buf)
	}
}

// GetRakNetBuffer gets a 32KB buffer from the pool (for RakNet)
func GetRakNetBuffer() *[]byte {
	return RakNetBufferPool.Get().(*[]byte)
}

// PutRakNetBuffer returns a RakNet buffer to the pool
func PutRakNetBuffer(buf *[]byte) {
	if buf != nil && cap(*buf) >= 32768 {
		*buf = (*buf)[:32768]
		RakNetBufferPool.Put(buf)
	}
}

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
