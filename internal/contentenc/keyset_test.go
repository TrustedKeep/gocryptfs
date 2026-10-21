package contentenc

import (
	"crypto/cipher"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
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

func newTestContentEnc(aeads ...cipher.AEAD) *ContentEnc {
	return New(newTestCore(), aeads, DefaultBS)
}

// aeadForKey has to answer for every index the ring holds, refuse anything past it, and refuse a
// hole — an entry whose key the key service would not return. The distinction matters:
// a hole is a specific, nameable index, not "out of range".
func TestAeadForKey(t *testing.T) {
	k0, k2 := newTestAEAD(1), newTestAEAD(2)
	be := newTestContentEnc(k0, nil, k2)

	if a, err := be.aeadForKey(0); err != nil || a != k0 {
		t.Errorf("index 0: got (%v, %v), want the first key", a, err)
	}
	if a, err := be.aeadForKey(2); err != nil || a != k2 {
		t.Errorf("index 2: got (%v, %v), want the third key", a, err)
	}
	if _, err := be.aeadForKey(1); !errors.Is(err, ErrKeyMissing) {
		t.Errorf("index 1 is a hole: got %v, want ErrKeyMissing", err)
	}
	if _, err := be.aeadForKey(3); !errors.Is(err, ErrKeyMissing) {
		t.Errorf("index 3 is past the end of the ring: got %v, want ErrKeyMissing", err)
	}
	if got := be.WriteKeyIdx(); got != 2 {
		t.Errorf("WriteKeyIdx = %d, want 2 (the newest entry)", got)
	}
}

// Every snapshot change publishes a whole new snapshot rather than growing the live one, so readers
// that are mid-decrypt keep a consistent view. Run this under -race with concurrent readers.
func TestInstallKeyConcurrent(t *testing.T) {
	be := newTestContentEnc(newTestAEAD(0))

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
				// Every install must carry the earlier keys into the new snapshot, so a
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
	var err error
	for i := uint16(1); i <= rotations && err == nil; i++ {
		if err = be.InstallKey(i, newTestAEAD(byte(i))); err == nil {
			_, err = be.SetWriteKey(i)
		}
	}
	close(stop)
	wg.Wait()
	if err != nil {
		t.Fatal(err)
	}

	if got := be.WriteKeyIdx(); got != rotations {
		t.Errorf("WriteKeyIdx = %d, want %d", got, rotations)
	}
	for i := 0; i <= rotations; i++ {
		if _, err := be.aeadForKey(uint16(i)); err != nil {
			t.Errorf("index %d: %v", i, err)
		}
	}
}

// Keys arrive at explicit indices, in order, and an install never moves the write key: a
// mount learning a peer's entry decides separately whether to write under it.
func TestInstallKey(t *testing.T) {
	k0, k1 := newTestAEAD(1), newTestAEAD(2)
	be := newTestContentEnc(k0)
	_, ctr := be.OpCounter()

	for _, idx := range []uint16{0, 2} {
		if err := be.InstallKey(idx, newTestAEAD(9)); err == nil {
			t.Errorf("InstallKey(%d) with one key held succeeded, want an error", idx)
		}
	}
	if a, err := be.aeadForKey(0); err != nil || a != k0 {
		t.Errorf("index 0 after refused installs: got (%v, %v), want the original key", a, err)
	}

	if err := be.InstallKey(1, k1); err != nil {
		t.Fatal(err)
	}
	if a, err := be.aeadForKey(1); err != nil || a != k1 {
		t.Errorf("index 1: got (%v, %v), want the installed key", a, err)
	}
	if err := be.InstallKey(2, nil); err != nil {
		t.Fatalf("installing a hole: %v", err)
	}
	if _, err := be.aeadForKey(2); !errors.Is(err, ErrKeyMissing) {
		t.Errorf("index 2 is a hole: got %v, want ErrKeyMissing", err)
	}
	if idx, c := be.OpCounter(); idx != 0 || c != ctr {
		t.Errorf("after installs the write key is %d (same counter: %v), want 0 and the same counter", idx, c == ctr)
	}
}

// The write key only moves forward, and only onto a key the mount holds. Each move hands out a
// fresh counter; a refused one leaves the write key and its counter alone.
func TestSetWriteKey(t *testing.T) {
	be := newTestContentEnc(newTestAEAD(1), newTestAEAD(2))
	if err := be.InstallKey(2, nil); err != nil {
		t.Fatal(err)
	}
	if err := be.InstallKey(3, newTestAEAD(4)); err != nil {
		t.Fatal(err)
	}
	_, before := be.OpCounter()

	for _, tc := range []struct {
		idx  uint16
		what string
	}{{0, "backwards"}, {2, "a hole"}, {4, "out of range"}} {
		if ctr, err := be.SetWriteKey(tc.idx); err == nil || ctr != nil {
			t.Errorf("SetWriteKey(%d), %s: got (%v, %v), want (nil, error)", tc.idx, tc.what, ctr, err)
		}
	}
	if idx, c := be.OpCounter(); idx != 1 || c != before {
		t.Errorf("after refused moves the write key is %d (same counter: %v), want 1 and the same counter", idx, c == before)
	}

	same, err := be.SetWriteKey(1)
	if err != nil {
		t.Fatalf("re-setting the current write key: %v", err)
	}
	if same == before {
		t.Error("re-setting the write key must still hand out a fresh counter")
	}
	ctr, err := be.SetWriteKey(3)
	if err != nil {
		t.Fatal(err)
	}
	if ctr == nil || ctr == same || ctr.Load() != 0 {
		t.Errorf("SetWriteKey(3) counter = %p (value %d), want a fresh zero counter", ctr, ctr.Load())
	}
	if idx, c := be.OpCounter(); idx != 3 || c != ctr {
		t.Errorf("OpCounter = (%d, same counter: %v), want (3, the counter SetWriteKey returned)", idx, c == ctr)
	}
	if got := be.WriteKeyIdx(); got != 3 {
		t.Errorf("WriteKeyIdx = %d, want 3", got)
	}
}

// A block written under a rotated-in key must decrypt under that key's index and fail under any
// other, which is what makes the index in the header load-bearing rather than decorative.
func TestBlockRoundTripAcrossKeys(t *testing.T) {
	be := newTestContentEnc(newTestAEAD(1))
	const newIdx = 1
	if err := be.InstallKey(newIdx, newTestAEAD(2)); err != nil {
		t.Fatal(err)
	}
	if _, err := be.SetWriteKey(newIdx); err != nil {
		t.Fatal(err)
	}

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

// The file header carries the index verbatim, including a non-zero one.
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

// The op counter counts the write key's nonce draws and nothing else: a write to a file created
// under an older key is not something any rotation can bound. A replaced counter keeps its count.
func TestOpCounter(t *testing.T) {
	be := newTestContentEnc(newTestAEAD(1))

	idx, c0 := be.OpCounter()
	if idx != 0 || c0.Load() != 0 {
		t.Fatalf("a fresh mount = (%d, %d), want (0, 0)", idx, c0.Load())
	}
	block := make([]byte, 16)
	for range 3 {
		be.EncryptBlock(block, 0, nil, 0)
	}
	if got := c0.Load(); got != 3 {
		t.Errorf("after 3 blocks = %d, want 3", got)
	}

	if err := be.InstallKey(1, newTestAEAD(2)); err != nil {
		t.Fatal(err)
	}
	be.EncryptBlock(block, 0, nil, 0)
	if got := c0.Load(); got != 4 {
		t.Errorf("index 0 is still the write key after an install: count = %d, want 4", got)
	}

	c1, err := be.SetWriteKey(1)
	if err != nil {
		t.Fatal(err)
	}
	be.EncryptBlock(block, 0, nil, 1)
	if c1.Load() != 1 || c0.Load() != 4 {
		t.Errorf("after one block under the new key: new = %d, old = %d, want 1 and 4", c1.Load(), c0.Load())
	}
	// A write to a file stamped with the old index keeps using the old key, so it is outside
	// the budget the threshold bounds.
	be.EncryptBlock(block, 0, nil, 0)
	if c1.Load() != 1 || c0.Load() != 4 {
		t.Errorf("after a write under the superseded key: new = %d, old = %d, want them unchanged at 1 and 4",
			c1.Load(), c0.Load())
	}
}

// A draw that loaded its snapshot before the write key moved lands on the replaced counter, so the
// sum over every counter handed out must equal the draws made under the write key. Run under -race.
func TestOpCountersConserveDraws(t *testing.T) {
	be := newTestContentEnc(newTestAEAD(1))
	_, first := be.OpCounter()
	counters := []*atomic.Uint64{first}

	const writers, draws = 4, 500
	start := make(chan struct{})
	var wg sync.WaitGroup
	for range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			block := make([]byte, 16)
			for range draws {
				be.EncryptBlock(block, 0, nil, 0)
			}
		}()
	}
	done := make(chan struct{})
	go func() { wg.Wait(); close(done) }()

	close(start)
	for running := true; running; {
		select {
		case <-done:
			running = false
		default:
		}
		ctr, err := be.SetWriteKey(0)
		if err != nil {
			<-done
			t.Fatal(err)
		}
		counters = append(counters, ctr)
	}

	var sum uint64
	for _, c := range counters {
		sum += c.Load()
	}
	if sum != writers*draws {
		t.Errorf("sum over %d counters = %d, want %d", len(counters), sum, writers*draws)
	}
}

// The learner is asked only for an index past the held prefix, holes included in that prefix. A
// learner that installs the key makes the lookup succeed; any other answer is ErrKeyMissing.
func TestKeyLearner(t *testing.T) {
	k0, k3 := newTestAEAD(1), newTestAEAD(4)
	be := newTestContentEnc(k0, nil, newTestAEAD(3))
	var asked []uint16
	be.SetKeyLearner(func(keyIdx uint16) bool {
		asked = append(asked, keyIdx)
		switch keyIdx {
		case 3:
			return be.InstallKey(3, k3) == nil
		case 9:
			// Claims success without installing anything.
			return true
		}
		return false
	})

	for idx := range uint16(3) {
		be.aeadForKey(idx)
	}
	if _, err := be.aeadForKey(1); !errors.Is(err, ErrKeyMissing) {
		t.Errorf("hole at index 1: got %v, want ErrKeyMissing", err)
	}
	if len(asked) != 0 {
		t.Fatalf("held indices asked the learner for %v, want nothing", asked)
	}

	if a, err := be.aeadForKey(3); err != nil || a != k3 {
		t.Errorf("index 3 via the learner: got (%v, %v), want the learned key", a, err)
	}
	if got := be.WriteKeyIdx(); got != 2 {
		t.Errorf("learning index 3 moved the write key to %d, want it at 2", got)
	}
	if _, err := be.aeadForKey(3); err != nil {
		t.Errorf("index 3 once learned: %v", err)
	}
	if _, err := be.aeadForKey(5); !errors.Is(err, ErrKeyMissing) {
		t.Errorf("index 5, not learned: got %v, want ErrKeyMissing", err)
	}
	if _, err := be.aeadForKey(9); !errors.Is(err, ErrKeyMissing) {
		t.Errorf("index 9, learner claims success but installs nothing: got %v, want ErrKeyMissing", err)
	}
	if want := []uint16{3, 5, 9}; !slices.Equal(asked, want) {
		t.Errorf("learner was asked for %v, want %v", asked, want)
	}
}

// A mount reading a block a sibling wrote under a key it has not learned yet learns it on the miss.
func TestDecryptLearnsSiblingKey(t *testing.T) {
	k0, k1 := newTestAEAD(1), newTestAEAD(2)
	sibling := newTestContentEnc(k0, k1)
	be := newTestContentEnc(k0)

	fileID := make([]byte, headerIDLen)
	fileID[0] = 3
	plain := []byte("written by a sibling mount")
	cBlock := sibling.EncryptBlock(plain, 0, fileID, 1)

	if _, err := be.DecryptBlock(cBlock, 0, fileID, 1); !errors.Is(err, ErrKeyMissing) {
		t.Errorf("without a learner: got %v, want ErrKeyMissing", err)
	}
	be.SetKeyLearner(func(keyIdx uint16) bool { return keyIdx == 1 && be.InstallKey(1, k1) == nil })
	got, err := be.DecryptBlock(cBlock, 0, fileID, 1)
	if err != nil || string(got) != string(plain) {
		t.Errorf("with a learner: got %q, err %v", got, err)
	}
}

// EnsureKey is the write path's resolve-first check: it learns the key if it can, and otherwise
// reports ErrKeyMissing instead of letting doEncryptBlock panic.
func TestEnsureKey(t *testing.T) {
	be := newTestContentEnc(newTestAEAD(1))
	if err := be.InstallKey(1, nil); err != nil {
		t.Fatal(err)
	}
	if err := be.EnsureKey(0); err != nil {
		t.Errorf("EnsureKey(0): %v", err)
	}
	for _, idx := range []uint16{1, 2} {
		if err := be.EnsureKey(idx); !errors.Is(err, ErrKeyMissing) {
			t.Errorf("EnsureKey(%d) without a learner: got %v, want ErrKeyMissing", idx, err)
		}
	}

	be.SetKeyLearner(func(keyIdx uint16) bool { return keyIdx == 2 && be.InstallKey(2, newTestAEAD(3)) == nil })
	if err := be.EnsureKey(2); err != nil {
		t.Fatalf("EnsureKey(2) with a learner: %v", err)
	}
	_, ctr := be.OpCounter()
	plain := []byte("under a learned key")
	got, err := be.DecryptBlock(be.EncryptBlock(plain, 0, nil, 2), 0, nil, 2)
	if err != nil || string(got) != string(plain) {
		t.Errorf("round-trip at learned index 2: got %q, err %v", got, err)
	}
	if ctr.Load() != 0 {
		t.Errorf("a draw under learned index 2 counted against write key 0: %d", ctr.Load())
	}
}

// The rotator still reads the counter at the final flush, after the keys are gone.
func TestWipeKeepsCounter(t *testing.T) {
	be := newTestContentEnc(newTestAEAD(1), newTestAEAD(2))
	be.EncryptBlock(make([]byte, 16), 0, nil, 1)
	idx, ctr := be.OpCounter()
	be.Wipe()
	if gotIdx, got := be.OpCounter(); gotIdx != idx || got != ctr || got.Load() != 1 {
		t.Errorf("after a wipe OpCounter = (%d, same counter: %v, %d), want (%d, the same counter, 1)",
			gotIdx, got == ctr, got.Load(), idx)
	}
}

// A wipe can overlap a mount that is still answering reads, so it has to publish a whole new
// snapshot rather than clear the live one: a reader must see either the old valid set or a clean
// hole. Run under -race with concurrent readers.
//
// Reads only. A write after a wipe still panics, because doEncryptBlock treats an unresolvable
// write index as a caller bug; nothing may be writing once the FUSE server is down.
func TestWipeConcurrent(t *testing.T) {
	be := newTestContentEnc(newTestAEAD(1), newTestAEAD(2))
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

	if _, err := be.aeadForKey(0); !errors.Is(err, ErrKeyMissing) {
		t.Errorf("after a wipe every index must report a hole: got %v", err)
	}
	if _, err := be.DecryptBlock(block, 0, nil, 0); err == nil {
		t.Error("a block must not decrypt after a wipe")
	}
}
