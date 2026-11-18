package update

import (
	"crypto/ed25519"
	"encoding/base64"
	"net/url"
)

// publicKeys — открытые ключи подписи релизов (ed25519, base64).
// Закрытый ключ хранится только у автора и в репозиторий не попадает.
var publicKeys = []string{
	"I9DijcKurDyLai1z01OUbk/rdji1Ln5WZ8QE6jnAC/U=",
}

// PublicKeys — встроенные ключи.
func PublicKeys() []ed25519.PublicKey {
	var out []ed25519.PublicKey
	for _, s := range publicKeys {
		if b, err := base64.StdEncoding.DecodeString(s); err == nil && len(b) == ed25519.PublicKeySize {
			out = append(out, ed25519.PublicKey(b))
		}
	}
	return out
}

func urlParse(s string) (*url.URL, error) { return url.Parse(s) }
