// Package protocol описывает формат кадров «мозаики» и авторизацию.
// Шифрование не изобретается: весь поток идёт внутри стандартного TLS 1.3
// (crypto/tls), авторизация — стандартный HMAC-SHA256.
package protocol

import (
	"encoding/binary"
	"errors"
	"io"
)

// Типы кадров.
const (
	TypePing byte = 0 // пустой, держит сессию
	TypeSYN  byte = 1 // открыть поток, payload = "host:port"
	TypeData byte = 2 // данные потока
	TypeFIN  byte = 3 // полузакрытие потока
	TypeRST  byte = 4 // сброс потока (ошибка соединения с целью)
)

// HeaderLen — размер заголовка кадра.
const HeaderLen = 7

// Frame — один кадр мультиплексора.
type Frame struct {
	Stream  uint32
	Type    byte
	Payload []byte
}

// MaxPayload — верхняя граница payload одного кадра.
const MaxPayload = 16 * 1024

var ErrTooBig = errors.New("frame payload too big")

// Size возвращает полный размер кадра на проводе.
func (f Frame) Size() int { return HeaderLen + len(f.Payload) }

// AppendFrame дописывает кадр в буфер.
func AppendFrame(dst []byte, f Frame) []byte {
	var h [HeaderLen]byte
	binary.BigEndian.PutUint32(h[0:4], f.Stream)
	h[4] = f.Type
	binary.BigEndian.PutUint16(h[5:7], uint16(len(f.Payload)))
	dst = append(dst, h[:]...)
	return append(dst, f.Payload...)
}

// ReadFrames читает все кадры из r до EOF.
func ReadFrames(r io.Reader, fn func(Frame) error) error {
	var h [HeaderLen]byte
	for {
		if _, err := io.ReadFull(r, h[:]); err != nil {
			if err == io.EOF {
				return nil
			}
			return err
		}
		n := int(binary.BigEndian.Uint16(h[5:7]))
		if n > MaxPayload {
			return ErrTooBig
		}
		p := make([]byte, n)
		if _, err := io.ReadFull(r, p); err != nil {
			return err
		}
		if err := fn(Frame{Stream: binary.BigEndian.Uint32(h[0:4]), Type: h[4], Payload: p}); err != nil {
			return err
		}
	}
}
