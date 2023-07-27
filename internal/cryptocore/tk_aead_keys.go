package cryptocore

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"sync"
	"time"

	cryptoutil "github.com/TrustedKeep/tkutils/v2/crypto"
	"github.com/TrustedKeep/tkutils/v2/kem"
	"github.com/TrustedKeep/tkutils/v2/lru"
	"github.com/rfjakob/gocryptfs/v2/internal/tkc"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

const (
	keyCacheSize  = 1000
	keyExpiration = time.Minute * 5
	bytesPerKey   = 1024 * 1024 * 1024 * 30 // 30 Gb per encryption key
	blockSize     = 4096                    // should match contentenc.DefaultBS

	lenUint64 = 8  //len of the block id
	fileIDLen = 16 // 128 bit random file id
)

var (
	keyMu sync.Mutex
	keys  *lru.Cache
)

func init() {
	keys = lru.NewLRUCacheWithExpire(keyCacheSize, keyExpiration, func(key string, value interface{}) {
		_, ok := value.([]byte)
		if ok {
			cryptoutil.Zeroize(value.([]byte))
		}
	})
}

func getKey(ad []byte, keyPool int) []byte {
	keyMu.Lock()
	defer keyMu.Unlock()

	var key []byte
	var ok bool
	//keypool -1 means using envelope encryption so we need to get the envelope key that our symmetric key was encrypted with
	if keyPool == -1 {
		id, wrapper, err := parseAD(ad)
		if err != nil {
			tlog.Warn.Printf("Unable to parse id and wrapper out of AD: %v", err)
			return []byte{}
		}

		tlog.Debug.Printf("Retrieving key %s", id)
		var envKey kem.Kem
		iKey := RetrieveKey(id, true)
		envKey, ok = iKey.(kem.Kem)
		if !ok {
			tlog.Warn.Printf("Unable to cast envKey to kem.Kem")
			return []byte{}
		}

		key, err = envKey.Unwrap(wrapper)
		if err != nil {
			tlog.Warn.Printf("Unable to unwrap symmetric key: %v", err)
			return []byte{}
		}
		return key

	} else {
		id := getKeyName(ad, keyPool)
		tlog.Debug.Printf("Retrieving key %s", id)
		iKey := RetrieveKey(id, false)
		key, ok = iKey.([]byte)
		if !ok {
			tlog.Warn.Printf("Unable to cast key to []byte:")
			return []byte{}
		}

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
		// ad = [blockNo.bigEndian fileID envelopeID wrappedKey]
		// so, first 8 bytes are bigendian uint64 containing block ID
		// next 16 bytes are the  first half of the file identifier
		id := hex.EncodeToString(additionalData[lenUint64 : lenUint64+fileIDLen])
		blockNum := binary.BigEndian.Uint64(additionalData[:lenUint64])
		blockKey := (int(blockNum) * blockSize) / bytesPerKey
		return fmt.Sprintf("%s/%d", id, blockKey)
	}
	// if we're using a keypool, figure out which key to use with a hash of the ad
	h := fnv.New32a()
	h.Write(additionalData)
	keyID := h.Sum32() % uint32(keyPool)
	return fmt.Sprintf("tkfs_kp/%d", keyID)
}

// parseAD takes the additionalData and breaks it up in to its components
func parseAD(ad []byte) (envKeyID string, wrapper []byte, err error) {
	// from content.go/concatAD, the AD passed in contains the fileID, block#, envelopeID, and wrappedKey as:
	// ad = [blockNo.bigEndian fileID envelopeID wrappedKey]
	// so, first 8 bytes are bigendian uint64 containing block ID
	// next 16 bytes are the file identifier
	// we can ignore these first two
	// the next 36 bytes are the uuid
	// the remainder is the wrapped key
	startLength := lenUint64 + fileIDLen

	if len(ad) <= startLength+tkc.EnvelopeIDLength {
		err = fmt.Errorf("ad is too short, envelopeID and wrapper are not present")
		return
	}
	envKeyID = string(ad[startLength : startLength+tkc.EnvelopeIDLength])
	wrapper = ad[startLength+tkc.EnvelopeIDLength:]
	return
}

// retrieveKey attempts to get either the envelope key or the symmetric from the cache, or failing that, from the kms
func RetrieveKey(id string, envelope bool) (iKey interface{}) {
	fmt.Printf("retrieve key id: %s, envelope: %t\n", id, envelope)
	var ok bool
	var err error

	//check for the key in the cache
	if iKey, ok = keys.Get(id); ok {
		return
	}
	//grab the key from the kms
	var tries int
	for {
		if envelope {
			iKey, err = tkc.Get().GetEnvelopeKey(id) // the envelope key used to wrap the aes key
		} else {
			iKey, err = tkc.Get().GetKey([]byte(id)) // the actual aes key
		}
		if err != nil {
			tlog.Warn.Printf("Unable to load key from KMS: %v", err)
			<-time.After(time.Second * 3)
			tries++
			// give up after 5 tries
			if tries > 5 {
				tlog.Warn.Printf("Giving up loading key from KMS after %d tries", tries)
				return
			}
			continue
		}
		keys.Add(id, iKey)
		break
	}
	return
}
