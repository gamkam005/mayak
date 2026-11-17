package protocol

import (
	"bytes"
	"math/rand"
	"testing"
)

func TestReasmShuffledOverlapping(t *testing.T) {
	r := rand.New(rand.NewSource(1))
	data := make([]byte, 200000)
	r.Read(data)
	type piece struct {
		off uint64
		b   []byte
	}
	var ps []piece
	// первая нарезка крупно, вторая (повтор) мелко — как после смены режима
	for off := 0; off < len(data); off += 50000 {
		e := min(off+50000, len(data))
		if r.Intn(3) != 0 { // часть кусков «потерялась»
			ps = append(ps, piece{uint64(off), data[off:e]})
		}
	}
	for off := 0; off < len(data); off += 7000 {
		e := min(off+7000, len(data))
		ps = append(ps, piece{uint64(off), data[off:e]})
	}
	r.Shuffle(len(ps), func(i, j int) { ps[i], ps[j] = ps[j], ps[i] })
	re := NewReasm()
	var got []byte
	for _, p := range ps {
		out, _ := re.Put(p.off, p.b)
		got = append(got, out...)
	}
	if !bytes.Equal(got, data) {
		t.Fatalf("mismatch: got %d bytes, want %d", len(got), len(data))
	}
}

func TestFrameParserSplit(t *testing.T) {
	var stream []byte
	for i := 0; i < 100; i++ {
		stream = AppendFrame(stream, Frame{Stream: uint32(i), Type: TypeData, Payload: bytes.Repeat([]byte{byte(i)}, i*37)})
	}
	var p FrameParser
	n := 0
	for off := 0; off < len(stream); off += 333 {
		p.Feed(stream[off:min(off+333, len(stream))], func(f Frame) {
			if int(f.Stream) != n || len(f.Payload) != n*37 {
				t.Fatalf("frame %d wrong", n)
			}
			n++
		})
	}
	if n != 100 {
		t.Fatalf("parsed %d frames", n)
	}
}
