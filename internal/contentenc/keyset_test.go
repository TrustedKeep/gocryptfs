package contentenc

import (
	"crypto/cipher"
	"sync"
	"testing"

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

// aeadForKey has to answer for every index the ring holds, refuse anything past it, and refuse a
// hole — an entry whose key the key service would not return at mount. The distinction matters:
// a hole is a specific, nameable index, not "out of range".
func TestAeadForKey(t *testing.T) {
	cc := cryptocore.New(make([]byte, cryptocore.KeyLen), cryptocore.BackendGoGCM, DefaultIVBits)
	k0, k2 := newTestAEAD(1), newTestAEAD(2)
	be := New(cc, []cipher.AEAD{k0, nil, k2}, DefaultBS)

	if a, err := be.aeadForKey(0); err != nil || a != k0 {
		t.Errorf("index 0: got (%v, %v), want the first key", a, err)
	}
	if a, err := be.aeadForKey(2); err != nil || a != k2 {
		t.Errorf("index 2: got (%v, %v), want the third key", a, err)
	}
	if _, err := be.aeadForKey(1); err == nil {
		t.Error("index 1 is a hole and must be an error, not a silent fallback")
	}
	if _, err := be.aeadForKey(3); err == nil {
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
				if _, err := be.aeadForKey(0); err != nil {
					t.Errorf("index 0 missing from a published snapshot: %v", err)
					return
				}
				// The write index must always resolve, whichever snapshot we land on.
				if _, err := be.aeadForKey(be.WriteKeyIdx()); err != nil {
					t.Errorf("write index did not resolve: %v", err)
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
		if _, err := be.aeadForKey(uint16(i)); err != nil {
			t.Errorf("index %d: %v", i, err)
		}
	}
}

// A block written under a rotated-in key must decrypt under that key's index and fail under any
// other, which is what makes the index in the header load-bearing rather than decorative.
func TestBlockRoundTripAcrossKeys(t *testing.T) {
	cc := cryptocore.New(make([]byte, cryptocore.KeyLen), cryptocore.BackendGoGCM, DefaultIVBits)
	be := New(cc, []cipher.AEAD{newTestAEAD(1)}, DefaultBS)
	newIdx := be.AddKey(newTestAEAD(2))

	fileID := make([]byte, headerIDLen)
	fileID[0] = 7
	plain := []byte("rotated content")
	cBlock := be.EncryptBlock(plain, 0, fileID, newIdx)

	got, err := be.DecryptBlock(cBlock, 0, fileID, newIdx)
	if err != nil || string(got) != string(plain) {
		t.Fatalf("round-trip at index %d: got %q, err %v", newIdx, got, err)
	}
	if _, err := be.DecryptBlock(cBlock, 0, fileID, 0); err == nil {
		t.Error("a block written under index 1 must not decrypt under index 0")
	}
}

// The file header carries the index verbatim, including a non-zero one. It sits outside the AAD,
// so a flipped index has to fail on the tag rather than on parsing.
func TestFileHeaderNonZeroKeyIdx(t *testing.T) {
	h := RandomHeader(1234)
	parsed, err := ParseHeader(h.Pack())
	if err != nil {
		t.Fatal(err)
	}
	if parsed.KeyIdx != 1234 {
		t.Errorf("KeyIdx = %d, want 1234", parsed.KeyIdx)
	}
	if parsed.Version != CurrentVersion {
		t.Errorf("Version = %d, want %d", parsed.Version, CurrentVersion)
	}
}

// The op counter is what auto-rotation reads. It counts the write key's nonce draws and nothing
// else: a rotation starts a fresh count (rotate() has already credited the outgoing one to the
// ring), and a write to a file created under an older key is not something any rotation can bound.
func TestOpCount(t *testing.T) {
	cc := cryptocore.New(make([]byte, cryptocore.KeyLen), cryptocore.BackendGoGCM, DefaultIVBits)
	be := New(cc, []cipher.AEAD{newTestAEAD(1)}, DefaultBS)

	if got := be.OpCount(); got != 0 {
		t.Fatalf("a fresh mount = %d, want 0", got)
	}
	block := make([]byte, 16)
	for range 3 {
		be.EncryptBlock(block, 0, nil, 0)
	}
	if got := be.OpCount(); got != 3 {
		t.Errorf("after 3 blocks = %d, want 3", got)
	}

	be.AddKey(newTestAEAD(2))
	if got := be.OpCount(); got != 0 {
		t.Errorf("after rotating = %d, want 0: the new key starts its own count", got)
	}
	be.EncryptBlock(block, 0, nil, 1)
	if got := be.OpCount(); got != 1 {
		t.Errorf("after one block under the new key = %d, want 1", got)
	}
	// A write to a file stamped with the old index keeps using the old key, so it is outside
	// the budget the threshold bounds.
	be.EncryptBlock(block, 0, nil, 0)
	if got := be.OpCount(); got != 1 {
		t.Errorf("after a write under the superseded key = %d, want it unchanged at 1", got)
	}
}

// A wipe can overlap a mount that is still answering reads, so it has to publish a whole new
// snapshot rather than clear the live one: a reader must see either the old valid set or a clean
// hole. Run under -race with concurrent readers.
//
// Reads only. A write after a wipe still panics, because doEncryptBlock treats an unresolvable
// write index as a caller bug; nothing may be writing once the FUSE server is down.
func TestWipeConcurrent(t *testing.T) {
	cc := cryptocore.New(make([]byte, cryptocore.KeyLen), cryptocore.BackendGoGCM, DefaultIVBits)
	be := New(cc, []cipher.AEAD{newTestAEAD(1), newTestAEAD(2)}, DefaultBS)
	block := be.EncryptBlock([]byte("content"), 0, nil, 0)

	const readers = 8
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range readers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 200 {
				// Either decrypts or reports a hole; neither may panic, and the
				// backend properties cryptoCore carries stay readable throughout.
				be.DecryptBlock(block, 0, nil, 0)
			}
		}()
	}
	close(start)
	be.Wipe()
	wg.Wait()

	if _, err := be.aeadForKey(0); err == nil {
		t.Error("after a wipe every index must report a hole")
	}
	if _, err := be.DecryptBlock(block, 0, nil, 0); err == nil {
		t.Error("a block must not decrypt after a wipe")
	}
}
