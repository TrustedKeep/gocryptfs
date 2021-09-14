package cryptocore

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"os"
	"sync"
	"time"

	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/tkc"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
	"golang.org/x/crypto/xts"
)

var _ cipher.AEAD = &xtsAead{}

type xtsAead struct {
	c        *xts.Cipher
	initOnce sync.Once
}

func newTkXts() *xtsAead {
	return new(xtsAead)
}

// NonceSize is N/A for xts
func (t *xtsAead) NonceSize() int {
	return 0
}

// Overhead is N/A for xts
func (t *xtsAead) Overhead() int {
	return 0
}

// Seal encrypts the plaintext using xts
func (t *xtsAead) Seal(dst, nonce, plaintext, additionalData []byte) (cipherText []byte) {
	t.ensureCipher()
	blockNum := binary.BigEndian.Uint64(additionalData[:8])

	plain := plaintext
	if rem := len(plaintext) % aes.BlockSize; rem > 0 {
		plain = make([]byte, len(plain)+(aes.BlockSize-rem))
		copy(plain, plaintext)
	}
	cipherText = make([]byte, len(plain))
	t.c.Encrypt(cipherText, plain, blockNum)
	return
}

// Open decrypts the plaintext
func (t *xtsAead) Open(dst, nonce, ciphertext, additionalData []byte) (plainText []byte, err error) {
	t.ensureCipher()
	blockNum := binary.BigEndian.Uint64(additionalData[:8])
	plainText = make([]byte, len(ciphertext))
	t.c.Decrypt(plainText, ciphertext, blockNum)
	return
}

func (t *xtsAead) ensureCipher() {
	t.initOnce.Do(func() {
		for {
			key, err := tkc.Get().GetKey([]byte("tk_xts_enc_key"))
			if err != nil {
				tlog.Warn.Printf("Error retrieving XTS key from KMS: %v", err)
				<-time.After(time.Second * 2)
				continue
			}
			if t.c, err = xts.NewCipher(func(blockKey []byte) (cipher.Block, error) {
				return aes.NewCipher(blockKey)
			}, key); err != nil {
				tlog.Fatal.Printf("Error creating XTS cipher block: %v", err)
				os.Exit(exitcodes.Other)
			}
			break
		}
	})
}
