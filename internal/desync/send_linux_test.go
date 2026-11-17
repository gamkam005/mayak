package desync

import (
	"net"
	"os"
	"testing"
)

// TCP_MD5SIG и IP_TTL ставятся без root (важно для Android).
func TestSockoptsUnprivileged(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	go func() {
		c, _ := ln.Accept()
		if c != nil {
			defer c.Close()
			b := make([]byte, 1)
			c.Read(b)
		}
	}()
	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	tc := c.(*net.TCPConn)
	if err := setMD5(tc, 5); err != nil {
		t.Fatalf("md5sig (uid %d): %v", os.Getuid(), err)
	}
	if err := setMD5(tc, 0); err != nil {
		t.Fatalf("md5sig off: %v", err)
	}
	if err := setTTL(tc, 3); err != nil {
		t.Fatal(err)
	}
	t.Logf("uid %d: TCP_MD5SIG и IP_TTL ставятся", os.Getuid())
}
