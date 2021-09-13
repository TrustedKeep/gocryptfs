package cryptocore

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	cryptoutil "github.com/TrustedKeep/tkutils/v2/crypto"
	"github.com/TrustedKeep/tkutils/v2/lru"
	"github.com/rfjakob/gocryptfs/v2/internal/tkc"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

const (
	keyCacheSize  = 1000
	keyExpiration = time.Minute * 5
	bytesPerKey   = 1024 * 1024 * 1024 * 30 // 30 Gb per encryption key
	blockSize     = 4096                    // should match contentenc.DefaultBS
)

var _ cipher.AEAD = &gcmAead{}

type gcmAead struct {
	ivSize int
	keys   *lru.Cache
	keyMu  sync.Mutex
}

func newTkAes(ivSize int) cipher.AEAD {
	g := &gcmAead{
		ivSize: ivSize,
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

// getKeyName returns the name of the key in the KMS for a given file/block.  This information
// is encoded in the additionalData parameter passed to the seal function.  Key name is in the form
// fileID/block, where fileID is the file node and block is calculated based on the number of
// bytes to encrypt with a single key...so, ~30Gb with 1 key means the first ~7 million blocks use the
// same encryption key
func getKeyName(additionalData []byte) string {
	// from content.go/concatAD, the AD passed in contains the fileID and block# as:
	// ad = [blockNo.bigEndian fileID]
	// so, first 8 bytes are bigendian uint64 containing block ID
	// next 8 bytes are the file identifier
	id := hex.EncodeToString(additionalData[8:])
	blockNum := binary.BigEndian.Uint64(additionalData[:8])
	blockKey := (int(blockNum) * blockSize) / bytesPerKey
	return fmt.Sprintf("%s/%d", id, blockKey)
}