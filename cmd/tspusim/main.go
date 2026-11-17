// tspusim — упрощённый «симулятор ТСПУ» для проверки МАЯКа на одной машине.
//
// TCP-ретранслятор между клиентом и сервером, который умеет:
//   - добавлять задержку (RTT), как до зарубежного VPS;
//   - «замораживать» соединение: после N байт от сервера к клиенту данные
//     молча перестают идти (соединение не рвётся — ровно как жалуются
//     пользователи в РФ);
//   - сбрасывать соединения с заданными SNI в ClientHello;
//   - ограничивать общую скорость канала.
//
// Это модель, а не настоящий ТСПУ: она проверяет логику обхода, но не
// заменяет проверку у реального провайдера.
package main

import (
	"encoding/binary"
	"flag"
	"io"
	"log"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var (
	listen  = flag.String("listen", "127.0.0.1:9443", "где слушать")
	to      = flag.String("to", "127.0.0.1:8443", "куда пересылать (сервер)")
	rtt     = flag.Duration("rtt", 60*time.Millisecond, "добавочный RTT")
	freeze  = flag.Int("freeze", 16384, "байт вниз на соединение до заморозки (0 = выкл)")
	blockS  = flag.String("block-sni", "", "через запятую: SNI, которые сбрасывать")
	mbit    = flag.Float64("mbit", 0, "ограничение скорости вниз, Мбит/с (0 = нет)")
	nConn   atomic.Int64
	nFrozen atomic.Int64
	nReset  atomic.Int64
)

type bucket struct {
	mu   sync.Mutex
	rate float64 // байт/с
	tok  float64
	last time.Time
}

func (b *bucket) take(n int) {
	if b == nil {
		return
	}
	for {
		b.mu.Lock()
		now := time.Now()
		b.tok += now.Sub(b.last).Seconds() * b.rate
		if b.tok > b.rate/10 {
			b.tok = b.rate / 10
		}
		b.last = now
		if b.tok >= float64(n) {
			b.tok -= float64(n)
			b.mu.Unlock()
			return
		}
		need := (float64(n) - b.tok) / b.rate
		b.mu.Unlock()
		time.Sleep(time.Duration(need * float64(time.Second)))
	}
}

var down *bucket

func main() {
	flag.Parse()
	if *mbit > 0 {
		down = &bucket{rate: *mbit * 1e6 / 8, last: time.Now()}
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	log.Printf("tspusim: %s -> %s rtt=%s freeze=%d block-sni=%q mbit=%.0f", *listen, *to, *rtt, *freeze, *blockS, *mbit)
	go func() {
		for range time.Tick(5 * time.Second) {
			log.Printf("stats: conns=%d frozen=%d sni-reset=%d", nConn.Load(), nFrozen.Load(), nReset.Load())
		}
	}()
	for {
		c, err := ln.Accept()
		if err != nil {
			continue
		}
		go handle(c)
	}
}

type chunk struct {
	b  []byte
	at time.Time
}

// pipe пересылает src→dst с задержкой half; limit>0 — заморозка после limit байт.
func pipe(dst, src net.Conn, half time.Duration, limit int, isDown bool, first func([]byte) bool) {
	ch := make(chan chunk, 4096)
	go func() {
		defer close(ch)
		buf := make([]byte, 32*1024)
		firstDone := first == nil
		for {
			n, err := src.Read(buf)
			if n > 0 {
				b := append([]byte(nil), buf[:n]...)
				if !firstDone {
					firstDone = true
					if !first(b) {
						return
					}
				}
				ch <- chunk{b, time.Now().Add(half)}
			}
			if err != nil {
				return
			}
		}
	}()
	sent := 0
	frozen := false
	for c := range ch {
		if d := time.Until(c.at); d > 0 {
			time.Sleep(d)
		}
		if frozen {
			continue // молча выбрасываем
		}
		b := c.b
		if limit > 0 && sent+len(b) > limit {
			b = b[:limit-sent]
			frozen = true
			nFrozen.Add(1)
		}
		if isDown {
			down.take(len(b))
		}
		if len(b) > 0 {
			if _, err := dst.Write(b); err != nil {
				break
			}
			sent += len(b)
		}
	}
	if !frozen {
		if tc, ok := dst.(*net.TCPConn); ok {
			_ = tc.CloseWrite()
		}
	} else {
		// замороженное соединение висит, пока клиент сам не сдастся
		_, _ = io.Copy(io.Discard, src)
	}
}

func handle(c net.Conn) {
	nConn.Add(1)
	s, err := net.Dial("tcp", *to)
	if err != nil {
		c.Close()
		return
	}
	half := *rtt / 2
	block := map[string]bool{}
	for _, x := range strings.Split(*blockS, ",") {
		if x = strings.TrimSpace(x); x != "" {
			block[x] = true
		}
	}
	checkSNI := func(b []byte) bool {
		if sni := parseSNI(b); sni != "" && block[sni] {
			nReset.Add(1)
			if tc, ok := c.(*net.TCPConn); ok {
				_ = tc.SetLinger(0) // RST
			}
			c.Close()
			s.Close()
			return false
		}
		return true
	}
	done := make(chan struct{}, 2)
	go func() { pipe(s, c, half, 0, false, checkSNI); done <- struct{}{} }()
	go func() { pipe(c, s, half, *freeze, true, nil); done <- struct{}{} }()
	<-done
	<-done
	c.Close()
	s.Close()
}

// parseSNI достаёт server_name из первого TLS ClientHello (если влезло в кусок).
func parseSNI(b []byte) string {
	if len(b) < 43 || b[0] != 0x16 || b[5] != 0x01 {
		return ""
	}
	p := 5 + 4 + 2 + 32 // record hdr, hs hdr, version, random
	if p >= len(b) {
		return ""
	}
	p += 1 + int(b[p]) // session id
	if p+2 > len(b) {
		return ""
	}
	p += 2 + int(binary.BigEndian.Uint16(b[p:])) // cipher suites
	if p >= len(b) {
		return ""
	}
	p += 1 + int(b[p]) // compression
	if p+2 > len(b) {
		return ""
	}
	end := p + 2 + int(binary.BigEndian.Uint16(b[p:]))
	p += 2
	for p+4 <= len(b) && p+4 <= end {
		typ := binary.BigEndian.Uint16(b[p:])
		l := int(binary.BigEndian.Uint16(b[p+2:]))
		p += 4
		if typ == 0 && p+5 <= len(b) {
			nl := int(binary.BigEndian.Uint16(b[p+3:]))
			if p+5+nl <= len(b) {
				return string(b[p+5 : p+5+nl])
			}
		}
		p += l
	}
	return ""
}
