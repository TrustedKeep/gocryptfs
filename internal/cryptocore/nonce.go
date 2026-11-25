package cryptocore

import (
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"log"
)

// RandBytes gets "n" random bytes from /dev/urandom or panics
func RandBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		// crypto/rand.Read() is documented to never return an
		// error, so this should never happen. Still, better safe than sorry.
		log.Panic("Failed to read random bytes: " + err.Error())
	}
	return b
}

// RandUint64 returns a secure random uint64
func RandUint64() uint64 {
	b := RandBytes(8)
	return binary.BigEndian.Uint64(b)
}

// randomNonceAEAD gives an AEAD the shape of cipher.NewGCMWithRandomNonce: Seal draws a random
// nonce and prepends it, Open reads it from the front, and both take a nil nonce.
type randomNonceAEAD struct {
	aead cipher.AEAD
}

func (a randomNonceAEAD) NonceSize() int { return 0 }

func (a randomNonceAEAD) Overhead() int { return a.aead.NonceSize() + a.aead.Overhead() }

func (a randomNonceAEAD) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	if len(nonce) != 0 {
		log.Panic("randomNonceAEAD: non-empty nonce")
	}
	nonce = RandBytes(a.aead.NonceSize())
	return a.aead.Seal(append(dst, nonce...), nonce, plaintext, additionalData)
}

func (a randomNonceAEAD) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	if len(nonce) != 0 {
		log.Panic("randomNonceAEAD: non-empty nonce")
	}
	n := a.aead.NonceSize()
	if len(ciphertext) < n+a.aead.Overhead() {
		return nil, errors.New("randomNonceAEAD: ciphertext too short")
	}
	return a.aead.Open(dst, ciphertext[:n], ciphertext[n:], additionalData)
}
