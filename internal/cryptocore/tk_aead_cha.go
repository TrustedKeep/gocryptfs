package cryptocore

import (
	"crypto/cipher"
	"sync"
	"time"

	cryptoutil "github.com/TrustedKeep/tkutils/v2/crypto"
	"github.com/TrustedKeep/tkutils/v2/lru"
	"github.com/rfjakob/gocryptfs/v2/internal/tkc"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
	"golang.org/x/crypto/chacha20poly1305"
)

var _ cipher.AEAD = &chaAead{}

type chaAead struct {
	keys  *lru.Cache
	keyMu sync.Mutex
}

func newTkCha() cipher.AEAD {
	g := &chaAead{
		keys: lru.NewLRUCacheWithExpire(keyCacheSize, keyExpiration, func(key string, value interface{}) {
			cryptoutil.Zeroize(value.([]byte))
		}),
	}
	return g
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
	aead, err := chacha20poly1305.NewX(t.getKey(additionalData))
	if err != nil {
		panic(err)
	}
	return aead
}

func (t *chaAead) getKey(ad []byte) []byte {
	t.keyMu.Lock()
	defer t.keyMu.Unlock()

	id := getKeyName(ad)
	tlog.Debug.Printf("Retrieving key %s", id)

	if iKey, cached := t.keys.Get(id); cached {
		return iKey.([]byte)
	}
	for {
		key, err := tkc.Get().GetKey([]byte(id))
		if err != nil {
			tlog.Warn.Printf("Unable to load key from KMS: %v", err)
			<-time.After(time.Second * 3)
			continue
		}
		t.keys.Add(id, key)
		return key
	}
}
