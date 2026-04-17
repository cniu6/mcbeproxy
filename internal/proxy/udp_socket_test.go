package proxy

import "testing"

type fakeUDPBufferConn struct {
	readSize   int
	writeSize  int
	readCalls  int
	writeCalls int
}

func (f *fakeUDPBufferConn) SetReadBuffer(bytes int) error {
	f.readCalls++
	f.readSize = bytes
	return nil
}

func (f *fakeUDPBufferConn) SetWriteBuffer(bytes int) error {
	f.writeCalls++
	f.writeSize = bytes
	return nil
}

func TestConfigureUDPConnBuffers(t *testing.T) {
	fake := &fakeUDPBufferConn{}
	if err := configureUDPConnBuffers(fake, 0); err != nil {
		t.Fatalf("configureUDPConnBuffers returned error: %v", err)
	}
	if fake.readCalls != 1 || fake.writeCalls != 1 {
		t.Fatalf("expected one read/write buffer call, got read=%d write=%d", fake.readCalls, fake.writeCalls)
	}
	if fake.readSize != defaultUDPSocketBufferSize || fake.writeSize != defaultUDPSocketBufferSize {
		t.Fatalf("unexpected buffer sizes: read=%d write=%d", fake.readSize, fake.writeSize)
	}
}

func TestDefaultBufferSizeCoversListenerPackets(t *testing.T) {
	if DefaultBufferSize < MaxUDPPacketSize {
		t.Fatalf("DefaultBufferSize=%d must be >= MaxUDPPacketSize=%d to avoid truncating MCBE UDP packets", DefaultBufferSize, MaxUDPPacketSize)
	}
}

func TestNormalizeUDPSocketBufferSize(t *testing.T) {
	tests := []struct {
		name      string
		requested int
		want      int
	}{
		{name: "os default", requested: -1, want: 0},
		{name: "auto", requested: 0, want: defaultUDPSocketBufferSize},
		{name: "floor", requested: 1024, want: MaxUDPPacketSize},
		{name: "exact", requested: 131072, want: 131072},
		{name: "ceiling", requested: maxUDPSocketBufferSize * 2, want: maxUDPSocketBufferSize},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := normalizeUDPSocketBufferSize(tt.requested); got != tt.want {
				t.Fatalf("normalizeUDPSocketBufferSize(%d)=%d, want %d", tt.requested, got, tt.want)
			}
		})
	}
}
