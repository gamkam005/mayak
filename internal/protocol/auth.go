package protocol

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"sync"
	"time"
)

// Токен авторизации: ts(8) | nonce(8) | session(16) | HMAC-SHA256(psk, ts|nonce|session)[:16].
// Кладётся в Cookie, чтобы запрос выглядел как обычный браузерный.
const tokenRaw = 8 + 8 + 16 + 16

// SessionID — идентификатор логической сессии клиента.
type SessionID [16]byte

func (s SessionID) String() string { return hex.EncodeToString(s[:]) }

// NewSessionID генерирует случайный идентификатор сессии.
func NewSessionID() SessionID {
	var s SessionID
	_, _ = rand.Read(s[:])
	return s
}

// DeriveKey превращает строку-секрет в ключ HMAC.
func DeriveKey(secret string) []byte {
	h := sha256.Sum256([]byte("mayak-v1|" + secret))
	return h[:]
}

func mac(key []byte, ts, nonce []byte, sid SessionID) []byte {
	m := hmac.New(sha256.New, key)
	m.Write(ts)
	m.Write(nonce)
	m.Write(sid[:])
	return m.Sum(nil)[:16]
}

// MakeToken формирует токен для одного запроса (у каждого запроса свой nonce).
func MakeToken(key []byte, sid SessionID) string {
	buf := make([]byte, 0, tokenRaw)
	var ts [8]byte
	binary.BigEndian.PutUint64(ts[:], uint64(time.Now().Unix()))
	var nonce [8]byte
	_, _ = rand.Read(nonce[:])
	buf = append(buf, ts[:]...)
	buf = append(buf, nonce[:]...)
	buf = append(buf, sid[:]...)
	buf = append(buf, mac(key, ts[:], nonce[:], sid)...)
	return base64.RawURLEncoding.EncodeToString(buf)
}

var (
	ErrBadToken = errors.New("bad token")
	ErrStale    = errors.New("stale token")
	ErrReplay   = errors.New("replayed token")
)

// Verifier проверяет токены и отсекает повторы (replay).
type Verifier struct {
	key    []byte
	window time.Duration
	mu     sync.Mutex
	seen   map[[8]byte]int64
	last   int64
}

func NewVerifier(key []byte) *Verifier {
	return &Verifier{key: key, window: 120 * time.Second, seen: map[[8]byte]int64{}}
}

// Verify возвращает SessionID, если токен валиден.
func (v *Verifier) Verify(tok string) (SessionID, error) {
	var sid SessionID
	raw, err := base64.RawURLEncoding.DecodeString(tok)
	if err != nil || len(raw) != tokenRaw {
		return sid, ErrBadToken
	}
	ts, nonce := raw[0:8], raw[8:16]
	copy(sid[:], raw[16:32])
	if !hmac.Equal(raw[32:48], mac(v.key, ts, nonce, sid)) {
		return sid, ErrBadToken
	}
	t := int64(binary.BigEndian.Uint64(ts))
	now := time.Now().Unix()
	if d := now - t; d > int64(v.window.Seconds()) || d < -int64(v.window.Seconds()) {
		return sid, ErrStale
	}
	var n [8]byte
	copy(n[:], nonce)
	v.mu.Lock()
	defer v.mu.Unlock()
	if now-v.last > 30 { // периодическая чистка
		for k, exp := range v.seen {
			if exp < now {
				delete(v.seen, k)
			}
		}
		v.last = now
	}
	if _, ok := v.seen[n]; ok {
		return sid, ErrReplay
	}
	v.seen[n] = now + int64(v.window.Seconds())*2
	return sid, nil
}
