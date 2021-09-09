package cryptocore

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/hex"
	"sync"
	"time"

	cryptoutil "github.com/TrustedKeep/tkutils/v2/crypto"
	"github.com/TrustedKeep/tkutils/v2/lru"
	"github.com/rfjakob/gocryptfs/v2/internal/tkc"
)

const (
	keyCacheSize  = 1000
	keyExpiration = time.Hour
)

var _ cipher.AEAD = &gcmAead{}

type gcmAead struct {
	configKey []byte
	ivSize    int
	keys      *lru.Cache
	keyMu     sync.Mutex
}

func newTkAes(configKey []byte, ivSize int) cipher.AEAD {
	g := &gcmAead{
		configKey: configKey,
		ivSize:    ivSize,
		keys: lru.NewLRUCacheWithExpire(keyCacheSize, keyExpiration, func(key string, value interface{}) {
			cryptoutil.Zeroize(value.([]byte))
		}),
	}
	return g
}

// NonceSize returns the size of the nonce that must be passed to Seal
// and Open.
func (t *gcmAead) NonceSize() int {
	return t.ivSize
}

// Overhead returns the maximum difference between the lengths of a
// plaintext and its ciphertext.
func (t *gcmAead) Overhead() int {
	return 16
}

// Seal encrypts and authenticates plaintext, authenticates the
// additional data and appends the result to dst, returning the updated
// slice. The nonce must be NonceSize() bytes long and unique for all
// time, for a given key.
//
// To reuse plaintext's storage for the encrypted output, use plaintext[:0]
// as dst. Otherwise, the remaining capacity of dst must not overlap plaintext.
func (t *gcmAead) Seal(dst, nonce, plaintext, additionalData []byte) []byte {
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
func (t *gcmAead) Open(dst, nonce, ciphertext, additionalData []byte) ([]byte, error) {
	return t.getAead(additionalData).Open(dst, nonce, ciphertext, additionalData)
}

func (t *gcmAead) getAead(additionalData []byte) (aead cipher.AEAD) {
	block, err := aes.NewCipher(t.getKey(additionalData))
	if err != nil {
		panic(err)
	}
	if aead, err = cipher.NewGCMWithNonceSize(block, t.ivSize); err != nil {
		panic(err)
	}
	return aead
}

func (t *gcmAead) getKey(ad []byte) []byte {
	// special case where we're decrypting the config file.  this should go away
	// once we're fully integrated with KMS
	if len(ad) == 8 {
		return t.configKey
	}
	t.keyMu.Lock()
	defer t.keyMu.Unlock()

	id := hex.EncodeToString(ad[8:])
	if iKey, cached := t.keys.Get(id); cached {
		return iKey.([]byte)
	}
	key, err := tkc.Get().GetKey([]byte(id))
	if err != nil {
		panic(err) // TODO: don't panic
	}
	t.keys.Add(id, key)
	return key
}
