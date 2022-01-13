package cryptocore

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/fnv"
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

var (
	keyMu sync.Mutex
	keys  *lru.Cache
)

func init() {
	keys = lru.NewLRUCacheWithExpire(keyCacheSize, keyExpiration, func(key string, value interface{}) {
		cryptoutil.Zeroize(value.([]byte))
	})
}

func getKey(ad []byte, keyPool int) []byte {
	keyMu.Lock()
	defer keyMu.Unlock()

	id := getKeyName(ad, keyPool)
	tlog.Debug.Printf("Retrieving key %s", id)

	if iKey, cached := keys.Get(id); cached {
		return iKey.([]byte)
	}
	for {
		key, err := tkc.Get().GetKey([]byte(id))
		if err != nil {
			tlog.Warn.Printf("Unable to load key from KMS: %v", err)
			<-time.After(time.Second * 3)
			continue
		}
		keys.Add(id, key)
		return key
	}
}

// getKeyName returns the name of the key in the KMS for a given file/block.  This information
// is encoded in the additionalData parameter passed to the seal function.  Key name is in the form
// fileID/block, where fileID is the file node and block is calculated based on the number of
// bytes to encrypt with a single key...so, ~30Gb with 1 key means the first ~7 million blocks use the
// same encryption key
func getKeyName(additionalData []byte, keyPool int) string {
	if keyPool <= 0 {
		// from content.go/concatAD, the AD passed in contains the fileID and block# as:
		// ad = [blockNo.bigEndian fileID]
		// so, first 8 bytes are bigendian uint64 containing block ID
		// next 8 bytes are the file identifier
		id := hex.EncodeToString(additionalData[8:])
		blockNum := binary.BigEndian.Uint64(additionalData[:8])
		blockKey := (int(blockNum) * blockSize) / bytesPerKey
		return fmt.Sprintf("%s/%d", id, blockKey)
	}
	// if we're using a keypool, figure out which key to use with a hash of the ad
	h := fnv.New32a()
	h.Write(additionalData)
	keyID := h.Sum32() % uint32(keyPool)
	return fmt.Sprintf("tkfs_kp/%d", keyID)
}
