package contentenc

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
)

// newTestAEAD builds a content AEAD from a master key whose bytes are all "seed".
func newTestAEAD(seed byte) cipher.AEAD {
	key := make([]byte, cryptocore.KeyLen)
	for i := range key {
		key[i] = seed
	}
	return cryptocore.New(key, cryptocore.BackendGoGCM, DefaultIVBits).AEADCipher
}

// aead has to answer for every index the ring holds, refuse anything past it, and refuse a nil
// entry, a key the mount does not hold. The distinction matters: a nil entry is a specific,
// nameable index, not "out of range".
func TestAeadForKey(t *testing.T) {
	cc := cryptocore.New(make([]byte, cryptocore.KeyLen), cryptocore.BackendGoGCM, DefaultIVBits)
	k0, k2 := newTestAEAD(1), newTestAEAD(2)
	be := New(cc, []cipher.AEAD{k0, nil, k2}, DefaultBS)
	ks := be.keys.Load()

	if a, err := ks.aead(0); err != nil || a != k0 {
		t.Errorf("index 0: got (%v, %v), want the first key", a, err)
	}
	if a, err := ks.aead(2); err != nil || a != k2 {
		t.Errorf("index 2: got (%v, %v), want the third key", a, err)
	}
	if _, err := ks.aead(1); err == nil {
		t.Error("index 1 is not held and must be an error, not a silent fallback")
	}
	if _, err := ks.aead(3); err == nil {
		t.Error("index 3 is past the end of the ring and must be an error")
	}
	if got := be.WriteKeyIdx(); got != 2 {
		t.Errorf("WriteKeyIdx = %d, want 2 (the newest entry)", got)
	}
}

// AddKey must publish a whole new snapshot rather than growing the live one, so readers that are
// mid-decrypt keep a consistent view. Run this under -race with concurrent readers.
func TestAddKeyConcurrent(t *testing.T) {
	cc := cryptocore.New(make([]byte, cryptocore.KeyLen), cryptocore.BackendGoGCM, DefaultIVBits)
	be := New(cc, []cipher.AEAD{newTestAEAD(0)}, DefaultBS)

	const readers = 8
	const rotations = 50
	stop := make(chan struct{})
	var wg sync.WaitGroup
	for i := 0; i < readers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				// AddKey must carry every earlier key into the new snapshot, so a
				// reader that lands on one mid-rotation still resolves index 0.
				if _, err := be.keys.Load().aead(0); err != nil {
					t.Errorf("index 0 missing from a published snapshot: %v", err)
					return
				}
				// The write index must always resolve, whichever snapshot we land on.
				if ks := be.keys.Load(); ks.aeads[ks.writeIdx] == nil {
					t.Error("write index did not resolve")
					return
				}
			}
		}()
	}
	for i := 1; i <= rotations; i++ {
		if got := be.AddKey(newTestAEAD(byte(i))); got != uint16(i) {
			t.Fatalf("AddKey returned %d, want %d", got, i)
		}
	}
	close(stop)
	wg.Wait()

	if got := be.WriteKeyIdx(); got != rotations {
		t.Errorf("WriteKeyIdx = %d, want %d", got, rotations)
	}
	for i := 0; i <= rotations; i++ {
		if _, err := be.keys.Load().aead(uint16(i)); err != nil {
			t.Errorf("index %d: %v", i, err)
		}
	}
}

// AddKey waits out an encryption still in flight, so none seals under the outgoing key after it
// returns.
func TestAddKeyWaitsForInFlightEncryption(t *testing.T) {
	cc := cryptocore.New(make([]byte, cryptocore.KeyLen), cryptocore.BackendGoGCM, DefaultIVBits)
	be := New(cc, []cipher.AEAD{newTestAEAD(1)}, DefaultBS)
	be.writeLock.RLock()
	done := make(chan struct{})
	go func() {
		be.AddKey(newTestAEAD(2))
		close(done)
	}()
	select {
	case <-done:
		t.Fatal("AddKey returned while an encryption was in flight")
	case <-time.After(50 * time.Millisecond):
	}
	be.writeLock.RUnlock()
	<-done
}

// Every block names the key that sealed it, so one file can hold blocks under several keys and
// each decrypts under its own. Relabelling a block with another held index must fail, not
// decrypt under the wrong key.
func TestBlocksNameTheirOwnKey(t *testing.T) {
	cc := cryptocore.New(make([]byte, cryptocore.KeyLen), cryptocore.BackendGoGCM, DefaultIVBits)
	be := New(cc, []cipher.AEAD{newTestAEAD(1)}, DefaultBS)

	fileID := make([]byte, headerIDLen)
	fileID[0] = 7
	// A full block first, so the two concatenate into one DecryptBlocks request.
	plain0 := bytes.Repeat([]byte("0"), DefaultBS)
	block0 := be.EncryptBlock(plain0, 0, fileID)
	newIdx := be.AddKey(newTestAEAD(2))
	plain1 := []byte("after the rotation")
	block1 := be.EncryptBlock(plain1, 1, fileID)

	for _, tc := range []struct {
		block   []byte
		blockNo uint64
		idx     uint16
		plain   []byte
	}{
		{block0, 0, 0, plain0},
		{block1, 1, newIdx, plain1},
	} {
		if got := binary.BigEndian.Uint16(tc.block); got != tc.idx {
			t.Errorf("block %d names index %d, want %d", tc.blockNo, got, tc.idx)
		}
		if got, err := be.DecryptBlock(tc.block, tc.blockNo, fileID); err != nil || !bytes.Equal(got, tc.plain) {
			t.Errorf("block %d: got %q, err %v", tc.blockNo, got, err)
		}
	}
	if got, err := be.DecryptBlocks(slices.Concat(block0, block1), 0, fileID); err != nil || !bytes.Equal(got, slices.Concat(plain0, plain1)) {
		t.Errorf("a request spanning both keys: err %v", err)
	}
	relabelled := slices.Clone(block1)
	binary.BigEndian.PutUint16(relabelled, 0)
	if _, err := be.DecryptBlock(relabelled, 1, fileID); err == nil {
		t.Error("a block sealed under index 1 must not decrypt when relabelled as index 0")
	}
	binary.BigEndian.PutUint16(relabelled, 2)
	if _, err := be.DecryptBlock(relabelled, 1, fileID); err == nil {
		t.Error("a block naming an index past the ring must be an error")
	}
}

// The op counter is what auto-rotation reads. Every nonce draw is under the write key and counts,
// including each block of a parallel EncryptBlocks; a rotation starts a fresh count (rotate() has
// already credited the outgoing one to the ring).
func TestOpCount(t *testing.T) {
	cc := cryptocore.New(make([]byte, cryptocore.KeyLen), cryptocore.BackendGoGCM, DefaultIVBits)
	be := New(cc, []cipher.AEAD{newTestAEAD(1)}, DefaultBS)

	if got := be.OpCount(); got != 0 {
		t.Fatalf("a fresh mount = %d, want 0", got)
	}
	block := make([]byte, 16)
	for range 3 {
		be.EncryptBlock(block, 0, nil)
	}
	if got := be.OpCount(); got != 3 {
		t.Errorf("after 3 blocks = %d, want 3", got)
	}

	be.AddKey(newTestAEAD(2))
	if got := be.OpCount(); got != 0 {
		t.Errorf("after rotating = %d, want 0: the new key starts its own count", got)
	}
	// 40 blocks takes the parallel path.
	blocks := make([][]byte, 40)
	for i := range blocks {
		blocks[i] = make([]byte, DefaultBS)
	}
	out := be.EncryptBlocks(blocks, 0, make([]byte, headerIDLen))
	if got := be.OpCount(); got != 40 {
		t.Errorf("after a 40-block request = %d, want 40", got)
	}
	for i := range blocks {
		if idx := binary.BigEndian.Uint16(out[uint64(i)*be.CipherBS():]); idx != 1 {
			t.Errorf("block %d names index %d, want the write key's 1", i, idx)
		}
	}
}

// A wipe can overlap a mount that is still answering reads, so it has to publish a whole new
// snapshot rather than clear the live one: a reader must see either the old valid set or the
// all-nil one. Run under -race with concurrent readers.
//
// Reads only. A write after a wipe panics, because EncryptBlock treats a wiped write key as a
// caller bug; nothing may be writing once the FUSE server is down.
func TestWipeConcurrent(t *testing.T) {
	cc := cryptocore.New(make([]byte, cryptocore.KeyLen), cryptocore.BackendGoGCM, DefaultIVBits)
	be := New(cc, []cipher.AEAD{newTestAEAD(1), newTestAEAD(2)}, DefaultBS)
	block := be.EncryptBlock([]byte("content"), 0, nil)

	const readers = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 200 {
				// Either decrypts or reports a missing key; neither may panic, and the
				// backend properties cryptoCore carries stay readable throughout.
				be.DecryptBlock(block, 0, nil)
			}
		}()
	}
	close(start)
	be.Wipe()
	wg.Wait()

	if _, err := be.keys.Load().aead(1); err == nil {
		t.Error("after a wipe every index must report a missing key")
	}
	if _, err := be.DecryptBlock(block, 0, nil); err == nil {
		t.Error("a block must not decrypt after a wipe")
	}
}

// A panic in one of EncryptBlocks' parallel workers reaches the caller, where the FUSE server's panic
// handler can halt the mount; left on the worker it would crash the process.
func TestEncryptBlocksParallelPanicReachesTheCaller(t *testing.T) {
	cc := cryptocore.New(make([]byte, cryptocore.KeyLen), cryptocore.BackendGoGCM, DefaultIVBits)
	be := New(cc, []cipher.AEAD{newTestAEAD(1)}, DefaultBS)
	be.Wipe()
	blocks := make([][]byte, 40)
	for i := range blocks {
		blocks[i] = make([]byte, DefaultBS)
	}
	defer func() {
		if recover() == nil {
			t.Error("encrypting under a wiped key did not panic")
		}
	}()
	be.EncryptBlocks(blocks, 0, make([]byte, headerIDLen))
}
