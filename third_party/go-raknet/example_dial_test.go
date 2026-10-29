package raknet_test

import (
	"fmt"

	"github.com/sandertv/go-raknet"
)

// The examples below run against a local listener instead of the public
// server they used to target. Examples cannot be skipped, so pointing them at
// the internet turned a build machine without connectivity into a hard
// failure unrelated to the library. A local listener keeps the example
// executable and its output deterministic everywhere.

func ExamplePing() {
	l, err := raknet.Listen("127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer func() {
		_ = l.Close()
	}()
	// The pong data is what Ping returns; a real server sends a MOTD that
	// starts with MCPE.
	l.PongData([]byte("MCPE;Example server;transparent;1.21.0;1;10;12345;Example;Survival;1;19132;19133;"))

	// Ping the target address. This will ping with a timeout of 5 seconds.
	// raknet.PingContext and raknet.PingTimeout may be used to cancel earlier.
	data, err := raknet.Ping(l.Addr().String())
	if err != nil {
		panic("error pinging " + l.Addr().String() + ": " + err.Error())
	}
	str := string(data)

	fmt.Println(str[:4])
	// Output: MCPE
}

func ExampleDial() {
	l, err := raknet.Listen("127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer func() {
		_ = l.Close()
	}()
	go func() {
		conn, err := l.Accept()
		if err != nil {
			return
		}
		defer func() {
			_ = conn.Close()
		}()
		// Echo one packet back to the client.
		p := make([]byte, 1500)
		n, err := conn.Read(p)
		if err != nil {
			return
		}
		_, _ = conn.Write(p[:n])
	}()

	// Dial a connection to the target address. This will time out after up to
	// 10 seconds. raknet.DialTimeout and raknet.DialContext may be used to
	// cancel at any other time.
	conn, err := raknet.Dial(l.Addr().String())
	if err != nil {
		panic("error connecting to " + l.Addr().String() + ": " + err.Error())
	}

	// Write a packet to the connection.
	data := []byte("Hello World!")
	if _, err := conn.Write(data); err != nil {
		panic("error writing packet to " + conn.RemoteAddr().String() + ": " + err.Error())
	}

	// Read the echoed packet back.
	p := make([]byte, 1500)
	n, err := conn.Read(p)
	if err != nil {
		panic("error reading packet from " + conn.RemoteAddr().String() + ": " + err.Error())
	}
	fmt.Println(string(p[:n]))

	// Close the connection after you're done with it.
	if err := conn.Close(); err != nil {
		panic("error closing connection: " + err.Error())
	}
	// Output: Hello World!
}
