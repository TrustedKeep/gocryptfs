// Package contentenc encrypts and decrypts file blocks.
package contentenc

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"log"
	"runtime"
	"sync"
	"sync/atomic"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

const (
	// DefaultBS is the default plaintext block size
	DefaultBS = 4096
	// DefaultIVBits is the default length of IV, in bits.
	// We always use 128-bit IVs for file content, but the
	// master key in the config file is encrypted with a 96-bit IV for
	// gocryptfs v1.2 and earlier. v1.3 switched to 128 bit.
	DefaultIVBits = 128
)

// keySet is an immutable snapshot of the content keys this mount holds. A nil entry is a hole:
// a ring entry whose key the key service would not return at mount.
type keySet struct {
	// aeads is indexed by key-ring index, so aeads[i] belongs to the ring's i-th entry.
	aeads []cipher.AEAD
	// ops counts the nonces drawn under writeIdx since this snapshot was published. A rotation
	// flushes the outgoing count and starts a fresh counter, so one is enough.
	ops *atomic.Uint64
	// writeIdx is the newest index, the one new content is encrypted under.
	writeIdx uint16
}

func newKeySet(aeads []cipher.AEAD) *keySet {
	if len(aeads) == 0 {
		log.Panic("contentenc: empty key set")
	}
	return &keySet{aeads: aeads, ops: new(atomic.Uint64), writeIdx: uint16(len(aeads) - 1)}
}

// ContentEnc is used to encipher and decipher file content.
type ContentEnc struct {
	// cryptoCore is the core the mount was built with. Only IVLen and IVGenerator are read from
	// it, and both are properties of the backend rather than of a key, so a rotation does not
	// replace it. Those reads are unsynchronized and on the hot path, so Wipe must never nil it.
	cryptoCore *cryptocore.CryptoCore
	// keys is read on every block by many goroutines and grows while mounted, so rotation
	// swaps in a whole new snapshot instead of mutating one under the readers.
	keys atomic.Pointer[keySet]
	// addKeyLock serializes the read-copy-store in AddKey against a concurrent rotation.
	addKeyLock sync.Mutex
	// plainBS is the plaintext block size. Usually 4096 bytes.
	plainBS uint64
	// cipherBS is the ciphertext block size. Usually 4128 bytes.
	// `cipherBS - plainBS`is the per-block overhead
	// (use BlockOverhead() to calculate it for you!)
	cipherBS uint64
	// All-zero block of size cipherBS, for fast compares
	allZeroBlock []byte
	// All-zero block of size IVBitLen/8, for fast compares
	allZeroNonce []byte

	// Ciphertext block "sync.Pool" pool. Always returns cipherBS-sized byte
	// slices (usually 4128 bytes).
	cBlockPool bPool
	// Plaintext block pool. Always returns plainBS-sized byte slices
	// (usually 4096 bytes).
	pBlockPool bPool
	// Ciphertext request data pool. Always returns byte slices of size
	// fuse.MAX_KERNEL_WRITE + encryption overhead.
	// Used by Read() to temporarily store the ciphertext as it is read from
	// disk.
	CReqPool bPool
	// Plaintext request data pool. Slice have size fuse.MAX_KERNEL_WRITE.
	PReqPool bPool
}

// New returns an initialized ContentEnc instance. "cc" is the primary (newest) key's core;
// "aeads" holds one content AEAD per key-ring index, with nil for an index whose key could not
// be unwrapped.
func New(cc *cryptocore.CryptoCore, aeads []cipher.AEAD, plainBS uint64) *ContentEnc {
	tlog.Debug.Printf("contentenc.New: plainBS=%d, keys=%d", plainBS, len(aeads))

	if fuse.MAX_KERNEL_WRITE%plainBS != 0 {
		log.Panicf("unaligned MAX_KERNEL_WRITE=%d", fuse.MAX_KERNEL_WRITE)
	}
	cipherBS := plainBS + uint64(cc.IVLen) + cryptocore.AuthTagLen
	// Take IV and GHASH overhead into account.
	cReqSize := int(fuse.MAX_KERNEL_WRITE / plainBS * cipherBS)
	// Unaligned reads (happens during fsck, could also happen with O_DIRECT?)
	// touch one additional ciphertext and plaintext block. Reserve space for the
	// extra block.
	cReqSize += int(cipherBS)
	pReqSize := fuse.MAX_KERNEL_WRITE + int(plainBS)
	c := &ContentEnc{
		cryptoCore:   cc,
		plainBS:      plainBS,
		cipherBS:     cipherBS,
		allZeroBlock: make([]byte, cipherBS),
		allZeroNonce: make([]byte, cc.IVLen),
		cBlockPool:   newBPool(int(cipherBS)),
		CReqPool:     newBPool(cReqSize),
		pBlockPool:   newBPool(int(plainBS)),
		PReqPool:     newBPool(pReqSize),
	}
	c.keys.Store(newKeySet(aeads))
	return c
}

// PlainBS returns the plaintext block size
func (be *ContentEnc) PlainBS() uint64 {
	return be.plainBS
}

// CipherBS returns the ciphertext block size
func (be *ContentEnc) CipherBS() uint64 {
	return be.cipherBS
}

// WriteKeyIdx is the key-ring index new content is encrypted under, stamped into every new file
// header and into the symlink/xattr prefixes. Reads must never use it — they honour whatever
// index the object they found carries.
func (be *ContentEnc) WriteKeyIdx() uint16 {
	return be.keys.Load().writeIdx
}

// AddKey installs a newly rotated key as the write key and returns its index. Copy-on-write:
// in-flight readers keep the snapshot they loaded. This is rotation's entry point on the
// content side.
func (be *ContentEnc) AddKey(aead cipher.AEAD) uint16 {
	be.addKeyLock.Lock()
	defer be.addKeyLock.Unlock()
	old := be.keys.Load()
	aeads := make([]cipher.AEAD, len(old.aeads), len(old.aeads)+1)
	copy(aeads, old.aeads)
	ks := newKeySet(append(aeads, aead))
	be.keys.Store(ks)
	return ks.writeIdx
}

// OpCount is how many nonces this mount has drawn under the current write key, which is what
// auto-rotation compares against its threshold. It restarts at every rotation and at every mount;
// the running total lives in the key ring.
func (be *ContentEnc) OpCount() uint64 {
	return be.keys.Load().ops.Load()
}

// aeadForKey selects the content AEAD for a key-ring index. On the read path keyIdx comes from a
// file header and is therefore untrusted input, so an index this mount has no key for is an
// error, not a panic.
func (be *ContentEnc) aeadForKey(keyIdx uint16) (cipher.AEAD, error) {
	ks := be.keys.Load()
	if int(keyIdx) >= len(ks.aeads) {
		return nil, fmt.Errorf("content is encrypted under key-ring index %d, but this mount holds %d key(s)", keyIdx, len(ks.aeads))
	}
	aead := ks.aeads[keyIdx]
	if aead == nil {
		return nil, fmt.Errorf("key-ring index %d could not be unwrapped at mount, so this content is unreadable", keyIdx)
	}
	return aead, nil
}

// DecryptBlocks decrypts a number of blocks that were encrypted under key-ring index keyIdx
// (from the file header).
func (be *ContentEnc) DecryptBlocks(ciphertext []byte, firstBlockNo uint64, fileID []byte, keyIdx uint16) ([]byte, error) {
	cBuf := bytes.NewBuffer(ciphertext)
	var err error
	pBuf := bytes.NewBuffer(be.PReqPool.Get()[:0])
	blockNo := firstBlockNo
	for cBuf.Len() > 0 {
		cBlock := cBuf.Next(int(be.cipherBS))
		var pBlock []byte
		pBlock, err = be.DecryptBlock(cBlock, blockNo, fileID, keyIdx)
		if err != nil {
			break
		}
		pBuf.Write(pBlock)
		be.pBlockPool.Put(pBlock)
		blockNo++
	}
	return pBuf.Bytes(), err
}

// concatAD concatenates the block number and the file ID to a byte blob
// that can be passed to AES-GCM as associated data (AD).
// Result is: aData = [blockNo.bigEndian fileID]
func concatAD(blockNo uint64, fileID []byte) (aData []byte) {
	if fileID != nil && len(fileID) != headerIDLen {
		// fileID is nil when decrypting the master key from the config file,
		// and for symlinks and xattrs.
		log.Panicf("wrong fileID length: %d", len(fileID))
	}
	if len(fileID) == 0 {
		fileID = make([]byte, headerIDLen)
	}
	const lenUint64 = 8
	// Preallocate space to save an allocation in append()
	aData = make([]byte, lenUint64, lenUint64+headerIDLen)
	binary.BigEndian.PutUint64(aData, blockNo)
	aData = append(aData, fileID...)
	return aData
}

// DecryptBlock - Verify and decrypt GCM block
//
// Corner case: A full-sized block of all-zero ciphertext bytes is translated
// to an all-zero plaintext block, i.e. file hole passthrough.
func (be *ContentEnc) DecryptBlock(ciphertext []byte, blockNo uint64, fileID []byte, keyIdx uint16) ([]byte, error) {
	// Empty block?
	if len(ciphertext) == 0 {
		return ciphertext, nil
	}

	// All-zero block?
	if bytes.Equal(ciphertext, be.allZeroBlock) {
		tlog.Debug.Printf("DecryptBlock: file hole encountered")
		return make([]byte, be.plainBS), nil
	}

	if len(ciphertext) < be.cryptoCore.IVLen {
		tlog.Warn.Printf("DecryptBlock: Block is too short: %d bytes", len(ciphertext))
		return nil, errors.New("block is too short")
	}

	// Extract nonce
	nonce := ciphertext[:be.cryptoCore.IVLen]
	if bytes.Equal(nonce, be.allZeroNonce) {
		// Bug in tmpfs?
		// https://github.com/rfjakob/gocryptfs/issues/56
		// http://www.spinics.net/lists/kernel/msg2370127.html
		return nil, errors.New("all-zero nonce")
	}
	ciphertextOrig := ciphertext
	ciphertext = ciphertext[be.cryptoCore.IVLen:]

	aead, err := be.aeadForKey(keyIdx)
	if err != nil {
		return nil, err
	}

	// Decrypt
	plaintext := be.pBlockPool.Get()
	plaintext = plaintext[:0]
	aData := concatAD(blockNo, fileID)
	plaintext, err = aead.Open(plaintext, nonce, ciphertext, aData)

	if err != nil {
		tlog.Debug.Printf("DecryptBlock: %s, len=%d", err.Error(), len(ciphertextOrig))
		tlog.Debug.Println(hex.Dump(ciphertextOrig))
		return nil, err
	}

	return plaintext, nil
}

// At some point, splitting the ciphertext into more groups will not improve
// performance, as spawning goroutines comes at a cost.
// 2 seems to work ok for now.
const encryptMaxSplit = 2

// encryptBlocksParallel splits the plaintext into parts and encrypts them
// in parallel.
func (be *ContentEnc) encryptBlocksParallel(plaintextBlocks [][]byte, ciphertextBlocks [][]byte, firstBlockNo uint64, fileID []byte, keyIdx uint16) {
	ncpu := runtime.NumCPU()
	if ncpu > encryptMaxSplit {
		ncpu = encryptMaxSplit
	}
	groupSize := len(plaintextBlocks) / ncpu
	var wg sync.WaitGroup
	for i := 0; i < ncpu; i++ {
		wg.Add(1)
		go func(i int) {
			low := i * groupSize
			high := (i + 1) * groupSize
			if i == ncpu-1 {
				// Last part picks up any left-over blocks
				//
				// The last part could run in the original goroutine, but
				// doing that complicates the code, and, surprisingly,
				// incurs a 1 % performance penalty.
				high = len(plaintextBlocks)
			}
			be.doEncryptBlocks(plaintextBlocks[low:high], ciphertextBlocks[low:high], firstBlockNo+uint64(low), fileID, keyIdx)
			wg.Done()
		}(i)
	}
	wg.Wait()
}

// EncryptBlocks is like EncryptBlock but takes multiple plaintext blocks.
// Returns a byte slice from CReqPool - so don't forget to return it
// to the pool.
func (be *ContentEnc) EncryptBlocks(plaintextBlocks [][]byte, firstBlockNo uint64, fileID []byte, keyIdx uint16) []byte {
	ciphertextBlocks := make([][]byte, len(plaintextBlocks))
	// For large writes, we parallelize encryption.
	if len(plaintextBlocks) >= 32 && runtime.NumCPU() >= 2 {
		be.encryptBlocksParallel(plaintextBlocks, ciphertextBlocks, firstBlockNo, fileID, keyIdx)
	} else {
		be.doEncryptBlocks(plaintextBlocks, ciphertextBlocks, firstBlockNo, fileID, keyIdx)
	}
	// Concatenate ciphertext into a single byte array.
	tmp := be.CReqPool.Get()
	out := bytes.NewBuffer(tmp[:0])
	for _, v := range ciphertextBlocks {
		out.Write(v)
		// Return the memory to cBlockPool
		be.cBlockPool.Put(v)
	}
	return out.Bytes()
}

// doEncryptBlocks is called by EncryptBlocks to do the actual encryption work
func (be *ContentEnc) doEncryptBlocks(in [][]byte, out [][]byte, firstBlockNo uint64, fileID []byte, keyIdx uint16) {
	for i, v := range in {
		out[i] = be.EncryptBlock(v, firstBlockNo+uint64(i), fileID, keyIdx)
	}
}

// EncryptBlock - Encrypt plaintext using a random nonce, under key-ring index keyIdx.
// blockNo and fileID are used as associated data.
// The output is nonce + ciphertext + tag.
func (be *ContentEnc) EncryptBlock(plaintext []byte, blockNo uint64, fileID []byte, keyIdx uint16) []byte {
	// Get a fresh random nonce
	nonce := be.cryptoCore.IVGenerator.Get()
	// Only the write key's draws are counted: rotation is additive, so a write to a file created
	// before a rotation stays under that file's own key and no rotation can bound it.
	if ks := be.keys.Load(); keyIdx == ks.writeIdx {
		ks.ops.Add(1)
	}
	return be.doEncryptBlock(plaintext, blockNo, fileID, nonce, keyIdx)
}

// doEncryptBlock is the backend for EncryptBlock and EncryptBlockNonce.
// blockNo and fileID are used as associated data.
// The output is nonce + ciphertext + tag.
func (be *ContentEnc) doEncryptBlock(plaintext []byte, blockNo uint64, fileID []byte, nonce []byte, keyIdx uint16) []byte {
	// Empty block?
	if len(plaintext) == 0 {
		return plaintext
	}
	if len(nonce) != be.cryptoCore.IVLen {
		log.Panic("wrong nonce length")
	}
	// Writes always use a key the mount holds (WriteKeyIdx()), so an unresolvable index here
	// is a caller bug, not a property of the data — unlike on the decrypt side, where it is
	// the header talking.
	aead, err := be.aeadForKey(keyIdx)
	if err != nil {
		log.Panicf("doEncryptBlock: %v", err)
	}
	// Block is authenticated with block number and file ID
	aData := concatAD(blockNo, fileID)
	// Get a cipherBS-sized block of memory, copy the nonce into it and truncate to
	// nonce length
	cBlock := be.cBlockPool.Get()
	copy(cBlock, nonce)
	cBlock = cBlock[0:len(nonce)]
	// Encrypt plaintext and append to nonce
	ciphertext := aead.Seal(cBlock, nonce, plaintext, aData)
	overhead := int(be.BlockOverhead())
	if len(plaintext)+overhead != len(ciphertext) {
		log.Panicf("unexpected ciphertext length: plaintext=%d, overhead=%d, ciphertext=%d",
			len(plaintext), overhead, len(ciphertext))
	}
	return ciphertext
}

// MergeBlocks - Merge newData into oldData at offset
// New block may be bigger than both newData and oldData
func (be *ContentEnc) MergeBlocks(oldData []byte, newData []byte, offset int) []byte {
	// Fastpath for small-file creation
	if len(oldData) == 0 && offset == 0 {
		return newData
	}

	// Make block of maximum size
	out := make([]byte, be.plainBS)

	// Copy old and new data into it
	copy(out, oldData)
	l := len(newData)
	copy(out[offset:offset+l], newData)

	// Crop to length
	outLen := len(oldData)
	newLen := offset + len(newData)
	if outLen < newLen {
		outLen = newLen
	}
	return out[0:outLen]
}

// Wipe tries to wipe secret keys from memory by dropping every reference to them.
//
// It publishes an all-nil snapshot rather than clearing the live one, so a reader that overlaps a
// wipe sees either the old valid set or a clean hole, never a torn read.
func (be *ContentEnc) Wipe() {
	be.addKeyLock.Lock()
	defer be.addKeyLock.Unlock()
	if ks := be.keys.Load(); ks != nil {
		be.keys.Store(newKeySet(make([]cipher.AEAD, len(ks.aeads))))
	}
	be.cryptoCore.Wipe()
}
