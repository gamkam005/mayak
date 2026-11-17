//go:build linux

package desync

import (
	"net"
	"strconv"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// Linux и Android: всё делается обычными setsockopt/send, root не нужен.

func control(c *net.TCPConn, f func(fd int)) error {
	rc, err := c.SyscallConn()
	if err != nil {
		return err
	}
	return rc.Control(func(fd uintptr) { f(int(fd)) })
}

func isV6(c *net.TCPConn) bool {
	a, ok := c.RemoteAddr().(*net.TCPAddr)
	return ok && a.IP.To4() == nil
}

func getTTL(c *net.TCPConn) int {
	ttl := 64
	_ = control(c, func(fd int) {
		if isV6(c) {
			if v, err := unix.GetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS); err == nil && v > 0 {
				ttl = v
			}
		} else if v, err := unix.GetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL); err == nil && v > 0 {
			ttl = v
		}
	})
	return ttl
}

func setTTL(c *net.TCPConn, ttl int) error {
	var e error
	err := control(c, func(fd int) {
		if isV6(c) {
			e = unix.SetsockoptInt(fd, unix.IPPROTO_IPV6, unix.IPV6_UNICAST_HOPS, ttl)
		} else {
			e = unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_TTL, ttl)
		}
	})
	if err != nil {
		return err
	}
	return e
}

// waitSent ждёт, пока ядро отдаст в сеть всё записанное (tcpi_notsent_bytes == 0),
// чтобы следующий send() стал отдельным сегментом с нужным TTL.
func waitSent(c *net.TCPConn, max time.Duration) {
	dl := time.Now().Add(max)
	for time.Now().Before(dl) {
		left := uint32(0)
		_ = control(c, func(fd int) {
			if ti, err := unix.GetsockoptTCPInfo(fd, unix.IPPROTO_TCP, unix.TCP_INFO); err == nil {
				left = ti.Notsent_bytes
			}
		})
		if left == 0 {
			return
		}
		time.Sleep(time.Millisecond)
	}
}

func rawWrite(c *net.TCPConn, f func(fd int) (int, error)) (int, error) {
	rc, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var n int
	var e error
	err = rc.Write(func(fd uintptr) bool {
		n, e = f(int(fd))
		return e != unix.EAGAIN
	})
	if err != nil {
		return n, err
	}
	return n, e
}

func sendDisorder(c *net.TCPConn, part []byte, r *Report) error {
	def := getTTL(c)
	if err := setTTL(c, 1); err != nil {
		r.Note = "TTL не меняется — обычный split"
		_, err := c.Write(part)
		r.Segments = append(r.Segments, len(part))
		return err
	}
	_, err := c.Write(part)
	r.Segments = append(r.Segments, len(part))
	waitSent(c, 100*time.Millisecond)
	_ = setTTL(c, def)
	return err
}

// sendFake: в сеть уходит фейк с малым TTL, но из той же страницы памяти,
// которую ядро потом использует для повторной передачи (vmsplice+splice с
// SPLICE_F_GIFT). Сразу после отправки в эту память кладутся настоящие байты,
// и ретрансмит несёт уже их. Так делает byedpi; root не требуется.
func sendFake(c *net.TCPConn, part, fake []byte, ttl int, md5 bool, r *Report) error {
	if len(fake) != len(part) {
		fake = part
	}
	def := getTTL(c)
	page := unix.Getpagesize()
	size := (len(part) + page - 1) / page * page
	mem, err := unix.Mmap(-1, 0, size, unix.PROT_READ|unix.PROT_WRITE, unix.MAP_PRIVATE|unix.MAP_ANONYMOUS)
	if err != nil {
		return fallbackSplit(c, part, r, "mmap: "+err.Error())
	}
	defer func() { _ = unix.Munmap(mem) }()
	copy(mem, fake)
	var fds [2]int
	if err := unix.Pipe(fds[:]); err != nil {
		return fallbackSplit(c, part, r, "pipe: "+err.Error())
	}
	defer unix.Close(fds[0])
	defer unix.Close(fds[1])
	if err := setTTL(c, ttl); err != nil {
		return fallbackSplit(c, part, r, "ttl: "+err.Error())
	}
	md5on := false
	if md5 {
		if err := setMD5(c, 5); err != nil {
			r.Note = "md5sig недоступен (" + err.Error() + "), фейк только с TTL"
		} else {
			md5on = true
		}
	}
	defer func() {
		if md5on {
			_ = setMD5(c, 0)
		}
	}()
	iov := []unix.Iovec{{Base: (*byte)(unsafe.Pointer(&mem[0]))}}
	iov[0].SetLen(len(part))
	n, err := unix.Vmsplice(fds[1], iov, unix.SPLICE_F_GIFT)
	if err != nil || n != len(part) {
		_ = setTTL(c, def)
		return fallbackSplit(c, part, r, "vmsplice")
	}
	sent, err := rawWrite(c, func(fd int) (int, error) {
		m, e := unix.Splice(fds[0], nil, fd, nil, n, 0)
		return int(m), e
	})
	r.Segments = append(r.Segments, sent)
	if err != nil {
		_ = setTTL(c, def)
		return err
	}
	waitSent(c, 100*time.Millisecond)
	// «отдано в сеть» ещё не значит «драйвер дочитал страницу»: даём ему
	// время, иначе в фейк попадут настоящие байты. Повтор раньше не
	// случится (TLP ≥ 10 мс, и он уйдёт с тем же малым TTL — безвредно).
	time.Sleep(15 * time.Millisecond)
	copy(mem, part) // ретрансмит пойдёт с настоящими байтами
	if md5on {
		_ = setMD5(c, 0)
		md5on = false
	}
	_ = setTTL(c, def)
	if r.Note == "" {
		r.Note = "fake ttl=" + itoa(ttl)
		if md5 {
			r.Note += " md5"
		}
	}
	return nil
}

func sendOOB(c *net.TCPConn, part []byte, r *Report) error {
	buf := append(append([]byte(nil), part...), 'a')
	n, err := rawWrite(c, func(fd int) (int, error) {
		return unix.SendmsgN(fd, buf, nil, nil, unix.MSG_OOB)
	})
	r.Segments = append(r.Segments, n)
	if err != nil {
		return err
	}
	waitSent(c, 50*time.Millisecond)
	return nil
}

func fallbackSplit(c *net.TCPConn, part []byte, r *Report, why string) error {
	r.Note = why + " — обычный split"
	_, err := c.Write(part)
	r.Segments = append(r.Segments, len(part))
	waitSent(c, 50*time.Millisecond)
	return err
}

func itoa(n int) string { return strconv.Itoa(n) }

// setMD5 включает (keylen>0) или снимает TCP MD5-подпись для пира. Сегмент с
// неожиданной MD5-опцией сервер молча отбрасывает (RFC 2385), а DPI его видит.
func setMD5(c *net.TCPConn, keylen int) error {
	ra, ok := c.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return nil
	}
	var sig unix.TCPMD5Sig
	if ip4 := ra.IP.To4(); ip4 != nil {
		sa := (*unix.RawSockaddrInet4)(unsafe.Pointer(&sig.Addr))
		sa.Family = unix.AF_INET
		copy(sa.Addr[:], ip4)
	} else {
		sa := (*unix.RawSockaddrInet6)(unsafe.Pointer(&sig.Addr))
		sa.Family = unix.AF_INET6
		copy(sa.Addr[:], ra.IP.To16())
	}
	sig.Keylen = uint16(keylen)
	var e error
	err := control(c, func(fd int) { e = unix.SetsockoptTCPMD5Sig(fd, unix.IPPROTO_TCP, unix.TCP_MD5SIG, &sig) })
	if err != nil {
		return err
	}
	return e
}
