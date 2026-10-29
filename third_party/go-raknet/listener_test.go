package raknet_test

import (
	"fmt"
	"github.com/sandertv/go-raknet"
	"testing"
	"time"
)

func TestListen(t *testing.T) {
	// Port 0 lets the OS pick a free port: a fixed 19132 collides with a real
	// server (or a previous run) and fails for reasons unrelated to the code.
	l, err := raknet.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		_, _ = raknet.Dial(l.Addr().String())
	}()
	c := make(chan error)
	go accept(l, c)

	select {
	case err := <-c:
		if err != nil {
			t.Error(err)
		}
	case <-time.After(time.Second * 3):
		t.Errorf("accepting connection took longer than 3 seconds")
	}
}

func accept(l *raknet.Listener, c chan error) {
	if _, err := l.Accept(); err != nil {
		c <- fmt.Errorf("error accepting connection: %v", err)
	}
	c <- nil
}
