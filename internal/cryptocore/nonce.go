package cryptocore

import (
	"crypto/rand"
	"encoding/binary"
	"log"
	"sync"

	"github.com/TrustedKeep/tkutils/v2/crypto"
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

type nonceGenerator struct {
	nonceLen  int // bytes
	nonceChan chan []byte
}

var (
	nonceGeneratorsLock sync.Mutex
	nonceGenerators     = make(map[int]*nonceGenerator)
)

// newNonceGenerator returns the process-wide generator for "nonceLen"-byte nonces, creating it on
// first use. Memoized because a mount builds one CryptoCore per key-ring entry, and a generator per
// core would park N-1 goroutines on pre-generated nonces for keys nothing writes under.
func newNonceGenerator(nonceLen int) *nonceGenerator {
	nonceGeneratorsLock.Lock()
	defer nonceGeneratorsLock.Unlock()
	if ng := nonceGenerators[nonceLen]; ng != nil {
		return ng
	}
	ng := &nonceGenerator{
		nonceLen:  nonceLen,
		nonceChan: make(chan []byte, 500),
	}
	go ng.gen()
	nonceGenerators[nonceLen] = ng
	return ng
}

func (n *nonceGenerator) gen() {
	for {
		n.nonceChan <- crypto.NextNonce(n.nonceLen)
	}
}

// Get a random "nonceLen"-byte nonce
func (n *nonceGenerator) Get() []byte {
	return <-n.nonceChan
}
