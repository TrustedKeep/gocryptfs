package cryptocore

import (
	"crypto/cipher"

	"golang.org/x/crypto/chacha20poly1305"
)

var _ cipher.AEAD = &chaAead{}

type chaAead struct {
}

func newTkCha() cipher.AEAD {
	return &chaAead{}
}

// NonceSize returns the size of the nonce that must be passed to Seal
// and Open.
func (t *chaAead) NonceSize() int {
	return 24
}

// Overhead returns the maximum difference between the lengths of a
// plaintext and its ciphertext.
func (t *chaAead) Overhead() int {
	return 16
}

// Seal encrypts and authenticates plaintext, authenticates the
// additional data and appends the result to dst, returning the updated
// slice. The nonce must be NonceSize() bytes long and unique for all
// time, for a given key.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0]
// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
func (t *chaAead) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
	return t.getAead(additionalData).Seal(dst, nonce, plaintext, additionalData)
}

// Open decrypts and authenticates ciphertext, authenticates the
// additional data and, if successful, appends the resulting plaintext
// to dst, returning the updated slice. The nonce must be NonceSize()
// bytes long and both it and the additional data must match the
// value passed to Seal.
//
// To reuse ciphertext's storage for the decrypted output, use ciphertext[:0]
// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
//
// Even if the function fails, the contents of dst, up to its capacity,
// may be overwritten.
func (t *chaAead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return t.getAead(additionalData).Open(dst, nonce, ciphertext, additionalData)
}

func (t *chaAead) getAead(additionalData []byte) (aead cipher.AEAD) {
	aead, err := chacha20poly1305.NewX(getKey(additionalData))
	if err != nil {
		panic(err)
	}
	return aead
}
