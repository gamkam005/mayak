package protocol

import "encoding/binary"

// Reasm собирает байтовый поток из кусков с произвольными смещениями
// (повторы и перекрытия допустимы) — как окно приёма в TCP. Благодаря
// смещениям повторную передачу можно нарезать иначе, чем первую.
type Reasm struct {
	Next uint64
	pend map[uint64][]byte
	size int
}

func NewReasm() *Reasm { return &Reasm{pend: map[uint64][]byte{}} }

// Buffered — сколько байт ждут недостающих кусков.
func (r *Reasm) Buffered() int { return r.size }

// Put добавляет кусок и возвращает новые непрерывные байты (или nil).
// dup=true, если кусок целиком уже был получен.
func (r *Reasm) Put(off uint64, b []byte) (out []byte, dup bool) {
	if len(b) == 0 {
		return nil, false
	}
	end := off + uint64(len(b))
	if end <= r.Next {
		return nil, true
	}
	if off < r.Next {
		b = b[r.Next-off:]
		off = r.Next
	}
	if old, ok := r.pend[off]; ok {
		if len(old) >= len(b) {
			return nil, true
		}
		r.size -= len(old)
	}
	r.pend[off] = b
	r.size += len(b)
	for {
		if c, ok := r.pend[r.Next]; ok {
			delete(r.pend, r.Next)
			r.size -= len(c)
			out = append(out, c...)
			r.Next += uint64(len(c))
			continue
		}
		// кусок, начинающийся раньше и перекрывающий Next (после перенарезки)
		found := false
		for o, c := range r.pend {
			e := o + uint64(len(c))
			if e <= r.Next {
				delete(r.pend, o)
				r.size -= len(c)
				continue
			}
			if o < r.Next {
				delete(r.pend, o)
				r.size -= len(c)
				c = c[r.Next-o:]
				out = append(out, c...)
				r.Next += uint64(len(c))
				found = true
				break
			}
		}
		if !found {
			break
		}
	}
	return out, false
}

// FrameParser режет непрерывный поток байт на кадры (кадр может прийти
// частями в разных кусках).
type FrameParser struct{ buf []byte }

func (p *FrameParser) Feed(b []byte, fn func(Frame)) {
	p.buf = append(p.buf, b...)
	for len(p.buf) >= HeaderLen {
		n := int(binary.BigEndian.Uint16(p.buf[5:7]))
		if len(p.buf) < HeaderLen+n {
			break
		}
		pl := make([]byte, n)
		copy(pl, p.buf[HeaderLen:HeaderLen+n])
		fn(Frame{Stream: binary.BigEndian.Uint32(p.buf[0:4]), Type: p.buf[4], Payload: pl})
		p.buf = p.buf[HeaderLen+n:]
	}
	if len(p.buf) == 0 {
		p.buf = nil
	}
}
