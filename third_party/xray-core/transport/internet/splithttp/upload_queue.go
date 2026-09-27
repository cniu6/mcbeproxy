package splithttp

// upload_queue is a specialized priorityqueue + channel to reorder generic
// packets by a sequence number

import (
	"container/heap"
	"io"
	"runtime"
	"sync"

	"github.com/xtls/xray-core/common/errors"
)

type Packet struct {
	Reader  io.ReadCloser
	Payload []byte
	Seq     uint64
}

type uploadQueue struct {
	nomore          bool
	pushedPackets   chan Packet
	writeCloseMutex sync.Mutex
	heap            uploadHeap
	nextSeq         uint64
	maxPackets      int

	// PATCHED (mcpeserverproxy): reader and closed were written by Close
	// (under writeCloseMutex) and read by Read without any lock. They get
	// their own mutex: Read cannot take writeCloseMutex, which Push holds
	// while blocked on the channel that Read drains.
	stateMu sync.Mutex
	reader  io.ReadCloser
	closed  bool
}

func (h *uploadQueue) getReader() io.ReadCloser {
	h.stateMu.Lock()
	defer h.stateMu.Unlock()
	return h.reader
}

func (h *uploadQueue) setReader(r io.ReadCloser) {
	h.stateMu.Lock()
	h.reader = r
	h.stateMu.Unlock()
}

func (h *uploadQueue) isClosed() bool {
	h.stateMu.Lock()
	defer h.stateMu.Unlock()
	return h.closed
}

func NewUploadQueue(maxPackets int) *uploadQueue {
	return &uploadQueue{
		pushedPackets: make(chan Packet, maxPackets),
		heap:          uploadHeap{},
		nextSeq:       0,
		maxPackets:    maxPackets,
	}
}

func (h *uploadQueue) Push(p Packet) error {
	h.writeCloseMutex.Lock()
	defer h.writeCloseMutex.Unlock()

	if h.isClosed() {
		return errors.New("packet queue closed")
	}
	if h.nomore {
		return errors.New("h.reader already exists")
	}
	if p.Reader != nil {
		h.nomore = true
	}
	h.pushedPackets <- p
	return nil
}

func (h *uploadQueue) Close() error {
	h.writeCloseMutex.Lock()
	defer h.writeCloseMutex.Unlock()

	if !h.isClosed() {
		h.stateMu.Lock()
		h.closed = true
		h.stateMu.Unlock()
		runtime.Gosched() // hope Read() gets the packet
	f:
		for {
			select {
			case p := <-h.pushedPackets:
				if p.Reader != nil {
					h.setReader(p.Reader)
				}
			default:
				break f
			}
		}
		close(h.pushedPackets)
	}
	if r := h.getReader(); r != nil {
		return r.Close()
	}
	return nil
}

func (h *uploadQueue) Read(b []byte) (int, error) {
	if r := h.getReader(); r != nil {
		return r.Read(b)
	}

	if h.isClosed() {
		return 0, io.EOF
	}

	if len(h.heap) == 0 {
		packet, more := <-h.pushedPackets
		if !more {
			return 0, io.EOF
		}
		if packet.Reader != nil {
			h.setReader(packet.Reader)
			return packet.Reader.Read(b)
		}
		heap.Push(&h.heap, packet)
	}

	for len(h.heap) > 0 {
		packet := heap.Pop(&h.heap).(Packet)
		n := 0

		if packet.Seq == h.nextSeq {
			copy(b, packet.Payload)
			n = min(len(b), len(packet.Payload))

			if n < len(packet.Payload) {
				// partial read
				packet.Payload = packet.Payload[n:]
				heap.Push(&h.heap, packet)
			} else {
				h.nextSeq = packet.Seq + 1
			}

			return n, nil
		}

		// misordered packet
		if packet.Seq > h.nextSeq {
			if len(h.heap) > h.maxPackets {
				// the "reassembly buffer" is too large, and we want to
				// constrain memory usage somehow. let's tear down the
				// connection, and hope the application retries.
				return 0, errors.New("packet queue is too large")
			}
			heap.Push(&h.heap, packet)
			packet2, more := <-h.pushedPackets
			if !more {
				return 0, io.EOF
			}
			heap.Push(&h.heap, packet2)
		}
	}

	return 0, nil
}

// heap code directly taken from https://pkg.go.dev/container/heap
type uploadHeap []Packet

func (h uploadHeap) Len() int           { return len(h) }
func (h uploadHeap) Less(i, j int) bool { return h[i].Seq < h[j].Seq }
func (h uploadHeap) Swap(i, j int)      { h[i], h[j] = h[j], h[i] }

func (h *uploadHeap) Push(x any) {
	// Push and Pop use pointer receivers because they modify the slice's length,
	// not just its contents.
	*h = append(*h, x.(Packet))
}

func (h *uploadHeap) Pop() any {
	old := *h
	n := len(old)
	x := old[n-1]
	*h = old[0 : n-1]
	return x
}
