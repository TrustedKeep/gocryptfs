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
	// DefaultIVBits is the AES-GCM IV length, in bits: the random 96-bit IV of
	// cipher.NewGCMWithRandomNonce.
	DefaultIVBits = 96
	// KeyIdxLen is the big-endian uint16 key-ring index in front of every ciphertext block, naming
	// the key that sealed it.
	KeyIdxLen = 2
)

// keySet is an immutable snapshot of the content keys this mount holds. A nil entry is a key the
// mount no longer holds, as after Wipe.
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

// aead selects the content AEAD for a key-ring index. The index comes from the block on disk and is
// therefore untrusted input, so one this mount has no key for is an error, not a panic.
func (ks *keySet) aead(keyIdx uint16) (cipher.AEAD, error) {
	if int(keyIdx) >= len(ks.aeads) {
		return nil, fmt.Errorf("content is encrypted under key-ring index %d, but this mount holds %d key(s)", keyIdx, len(ks.aeads))
	}
	aead := ks.aeads[keyIdx]
	if aead == nil {
		return nil, fmt.Errorf("this mount no longer holds the key for key-ring index %d, so this content is unreadable", keyIdx)
	}
	return aead, nil
}

// ContentEnc is used to encipher and decipher file content.
type ContentEnc struct {
	// cryptoCore is the core the mount was built with. Only IVLen is read from
	// it, and that is a property of the backend rather than of a key, so a rotation does not
	// replace it. Those reads are unsynchronized and on the hot path, so Wipe must never nil it.
	cryptoCore *cryptocore.CryptoCore
	// keys is read on every block by many goroutines and grows while mounted, so rotation
	// swaps in a whole new snapshot instead of mutating one under the readers.
	keys atomic.Pointer[keySet]
	// writeLock is held shared for a whole encryption and exclusively by AddKey and Wipe, so once a
	// rotation returns nothing is still sealing under the outgoing key.
	writeLock sync.RWMutex
	// plainBS is the plaintext block size. Usually 4096 bytes.
	plainBS uint64
	// cipherBS is the ciphertext block size. Usually 4126 bytes.
	// `cipherBS - plainBS`is the per-block overhead
	// (use BlockOverhead() to calculate it for you!)
	cipherBS uint64
	// All-zero block of size cipherBS, for fast compares
	allZeroBlock []byte
	// All-zero block of size IVBitLen/8, for fast compares
	allZeroNonce []byte

	// Ciphertext block "sync.Pool" pool. Always returns cipherBS-sized byte
	// slices (usually 4126 bytes).
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
// "aeads" holds one content AEAD per key-ring index.
func New(cc *cryptocore.CryptoCore, aeads []cipher.AEAD, plainBS uint64) *ContentEnc {
	tlog.Debug.Printf("contentenc.New: plainBS=%d, keys=%d", plainBS, len(aeads))

	if fuse.MAX_KERNEL_WRITE%plainBS != 0 {
		log.Panicf("unaligned MAX_KERNEL_WRITE=%d", fuse.MAX_KERNEL_WRITE)
	}
	cipherBS := plainBS + KeyIdxLen + uint64(cc.IVLen) + cryptocore.AuthTagLen
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

// WriteKeyIdx is the key-ring index new content is encrypted under. Reads must never use it: they
// honour whatever index the block they found carries.
func (be *ContentEnc) WriteKeyIdx() uint16 {
	return be.keys.Load().writeIdx
}

// AddKey installs a newly rotated key as the write key and returns its index, once no encryption
// is still running under the outgoing one. Readers are not waited for: they keep the snapshot they loaded.
func (be *ContentEnc) AddKey(aead cipher.AEAD) uint16 {
	be.writeLock.Lock()
	defer be.writeLock.Unlock()
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

// DecryptBlocks decrypts a number of blocks, each under the key-ring index it names.
func (be *ContentEnc) DecryptBlocks(ciphertext []byte, firstBlockNo uint64, fileID []byte) ([]byte, error) {
	ks := be.keys.Load()
	cBuf := bytes.NewBuffer(ciphertext)
	var err error
	pBuf := bytes.NewBuffer(be.PReqPool.Get()[:0])
	blockNo := firstBlockNo
	for cBuf.Len() > 0 {
		cBlock := cBuf.Next(int(be.cipherBS))
		var pBlock []byte
		pBlock, err = be.decryptBlock(cBlock, blockNo, fileID, ks)
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
func (be *ContentEnc) DecryptBlock(ciphertext []byte, blockNo uint64, fileID []byte) ([]byte, error) {
	return be.decryptBlock(ciphertext, blockNo, fileID, be.keys.Load())
}

func (be *ContentEnc) decryptBlock(ciphertext []byte, blockNo uint64, fileID []byte, ks *keySet) ([]byte, error) {
	// Empty block?
	if len(ciphertext) == 0 {
		return ciphertext, nil
	}

	// All-zero block?
	if bytes.Equal(ciphertext, be.allZeroBlock) {
		tlog.Debug.Printf("DecryptBlock: file hole encountered")
		return make([]byte, be.plainBS), nil
	}

	if len(ciphertext) < KeyIdxLen+be.cryptoCore.IVLen {
		tlog.Warn.Printf("DecryptBlock: Block is too short: %d bytes", len(ciphertext))
		return nil, errors.New("block is too short")
	}
	keyIdx := binary.BigEndian.Uint16(ciphertext)
	sealed := ciphertext[KeyIdxLen:]

	// Extract nonce
	nonce := sealed[:be.cryptoCore.IVLen]
	if bytes.Equal(nonce, be.allZeroNonce) {
		// Bug in tmpfs?
		// https://github.com/rfjakob/gocryptfs/issues/56
		// http://www.spinics.net/lists/kernel/msg2370127.html
		return nil, errors.New("all-zero nonce")
	}
	aead, err := ks.aead(keyIdx)
	if err != nil {
		return nil, err
	}

	// Decrypt
	plaintext := be.pBlockPool.Get()
	plaintext = plaintext[:0]
	aData := concatAD(blockNo, fileID)
	plaintext, err = aead.Open(plaintext, nil, sealed, aData)

	if err != nil {
		tlog.Debug.Printf("DecryptBlock: %s, len=%d", err.Error(), len(ciphertext))
		tlog.Debug.Println(hex.Dump(ciphertext))
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
func (be *ContentEnc) encryptBlocksParallel(plaintextBlocks [][]byte, ciphertextBlocks [][]byte, firstBlockNo uint64, fileID []byte, ks *keySet) {
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
			be.doEncryptBlocks(plaintextBlocks[low:high], ciphertextBlocks[low:high], firstBlockNo+uint64(low), fileID, ks)
			wg.Done()
		}(i)
	}
	wg.Wait()
}

// EncryptBlocks is like EncryptBlock but takes multiple plaintext blocks.
// Returns a byte slice from CReqPool - so don't forget to return it
// to the pool.
func (be *ContentEnc) EncryptBlocks(plaintextBlocks [][]byte, firstBlockNo uint64, fileID []byte) []byte {
	be.writeLock.RLock()
	defer be.writeLock.RUnlock()
	ks := be.keys.Load()
	ciphertextBlocks := make([][]byte, len(plaintextBlocks))
	// For large writes, we parallelize encryption.
	if len(plaintextBlocks) >= 32 && runtime.NumCPU() >= 2 {
		be.encryptBlocksParallel(plaintextBlocks, ciphertextBlocks, firstBlockNo, fileID, ks)
	} else {
		be.doEncryptBlocks(plaintextBlocks, ciphertextBlocks, firstBlockNo, fileID, ks)
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
func (be *ContentEnc) doEncryptBlocks(in [][]byte, out [][]byte, firstBlockNo uint64, fileID []byte, ks *keySet) {
	for i, v := range in {
		out[i] = be.encryptBlock(v, firstBlockNo+uint64(i), fileID, ks)
	}
}

// EncryptBlock - Encrypt plaintext using a random nonce, under the write key.
// blockNo and fileID are used as associated data.
// The output is keyIdx + nonce + ciphertext + tag.
func (be *ContentEnc) EncryptBlock(plaintext []byte, blockNo uint64, fileID []byte) []byte {
	be.writeLock.RLock()
	defer be.writeLock.RUnlock()
	return be.encryptBlock(plaintext, blockNo, fileID, be.keys.Load())
}

func (be *ContentEnc) encryptBlock(plaintext []byte, blockNo uint64, fileID []byte, ks *keySet) []byte {
	// Empty block?
	if len(plaintext) == 0 {
		return plaintext
	}
	// Only Wipe leaves the write key nil, and nothing writes after it.
	aead := ks.aeads[ks.writeIdx]
	if aead == nil {
		log.Panicf("EncryptBlock: the write key (index %d) has been wiped", ks.writeIdx)
	}
	ks.ops.Add(1)
	// Block is authenticated with block number and file ID. The key index is not: the tag already
	// binds the key that sealed the block.
	aData := concatAD(blockNo, fileID)
	cBlock := be.cBlockPool.Get()[:KeyIdxLen]
	binary.BigEndian.PutUint16(cBlock, ks.writeIdx)
	// Seal draws the nonce and writes it ahead of the ciphertext.
	ciphertext := aead.Seal(cBlock, nil, plaintext, aData)
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
// wipe sees either the old valid set or the all-nil one, never a torn read.
func (be *ContentEnc) Wipe() {
	be.writeLock.Lock()
	defer be.writeLock.Unlock()
	if ks := be.keys.Load(); ks != nil {
		be.keys.Store(newKeySet(make([]cipher.AEAD, len(ks.aeads))))
	}
	be.cryptoCore.Wipe()
}
