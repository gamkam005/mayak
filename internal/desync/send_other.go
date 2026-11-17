//go:build !linux

package desync

import (
	"net"
	"time"
)

// Не Linux (Windows, macOS): доступны tlsrec и split; disorder/fake/oob
// сводятся к split.

func waitSent(c *net.TCPConn, max time.Duration) { time.Sleep(2 * time.Millisecond) }

func plain(c *net.TCPConn, part []byte, r *Report) error {
	r.Note = "на этой ОС приём недоступен — обычный split"
	_, err := c.Write(part)
	r.Segments = append(r.Segments, len(part))
	waitSent(c, 0)
	return err
}

func sendDisorder(c *net.TCPConn, part []byte, r *Report) error { return plain(c, part, r) }
func sendFake(c *net.TCPConn, part, fake []byte, ttl int, md5 bool, r *Report) error {
	return plain(c, part, r)
}
func sendOOB(c *net.TCPConn, part []byte, r *Report) error { return plain(c, part, r) }
