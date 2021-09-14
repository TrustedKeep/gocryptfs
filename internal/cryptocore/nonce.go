package cryptocore

import (
	"crypto/rand"
	"encoding/binary"
	"log"

	"github.com/TrustedKeep/tkutils/v2/crypto"
)

// RandBytes gets "n" random bytes from /dev/urandom or panics
func RandBytes(n int) []byte {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		log.Panic("Failed to read random bytes: " + err.Error())
	}
	return b
}

// RandUint64 returns a secure random uint64
func RandUint64() uint64 {
	b := RandBytes(8)
	return binary.BigEndian.Uint64(b)
}

type nonceGenerator struct {
	nonceLen  int // bytes
	nonceChan chan []byte
}

func newNonceGenerator(nonceLen int) *nonceGenerator {
	ng := &nonceGenerator{
		nonceLen: nonceLen,
		// nonceChan: make(chan []byte, 500),
	}
	if nonceLen > 0 {
		ng.nonceChan = make(chan []byte, 500)
		go ng.gen()
	}
	return ng
}

func (n *nonceGenerator) gen() {
	for {
		n.nonceChan <- crypto.NextNonce(n.nonceLen)
	}
}

// Get a random "nonceLen"-byte nonce
func (n *nonceGenerator) Get() []byte {
	if n.nonceLen == 0 {
		return []byte{}
	}
	return <-n.nonceChan
}
