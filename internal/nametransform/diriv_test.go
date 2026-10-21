package nametransform

import (
	"bytes"
	"errors"
	"os"
	"slices"
	"sync"
	"syscall"
	"testing"

	"github.com/rfjakob/eme"

	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
)

// newTestEMECipher builds a name cipher from a master key whose first byte is seed.
func newTestEMECipher(seed byte) *eme.EMECipher {
	key := make([]byte, cryptocore.KeyLen)
	key[0] = seed
	return cryptocore.New(key, cryptocore.BackendGoGCM, contentenc.DefaultIVBits).EMECipher
}

// newDirIVTestInstance holds keys name keys; index i is newTestEMECipher(i+1).
func newDirIVTestInstance(deterministicNames bool, keys int) *NameTransform {
	ciphers := make([]*eme.EMECipher, keys)
	for i := range ciphers {
		ciphers[i] = newTestEMECipher(byte(i + 1))
	}
	return New(ciphers, true, 0, true, nil, deterministicNames)
}

func openTestDir(t *testing.T) (dirfd int, path string) {
	t.Helper()
	path = t.TempDir()
	fd, err := syscall.Open(path, syscall.O_DIRECTORY|syscallcompat.O_PATH, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { syscall.Close(fd) })
	return fd, path
}

// The diriv file is 18 bytes: a 16-byte IV plus the key-ring index, and the index has to survive
// the round trip in both name modes that have a diriv. -deterministic-names inverts the all-zero
// rule — there it is the only legal IV — so both directions of that check are asserted.
func TestDirIVRoundTrip(t *testing.T) {
	for _, deterministic := range []bool{false, true} {
		n := newDirIVTestInstance(deterministic, 4)
		dirfd, path := openTestDir(t)
		if err := WriteDirIVAt(dirfd, 3, deterministic); err != nil {
			t.Fatalf("deterministic=%v: WriteDirIVAt: %v", deterministic, err)
		}
		st, err := os.Stat(path + "/" + DirIVFilename)
		if err != nil {
			t.Fatal(err)
		}
		if st.Size() != DirIVFileLen {
			t.Errorf("deterministic=%v: diriv is %d bytes, want %d", deterministic, st.Size(), DirIVFileLen)
		}
		iv, keyIdx, err := n.ReadDirIVAt(dirfd)
		if err != nil {
			t.Fatalf("deterministic=%v: ReadDirIVAt: %v", deterministic, err)
		}
		if len(iv) != DirIVLen {
			// eme hard-panics on a tweak that is not exactly 16 bytes, so the index must
			// never be handed back as part of the IV.
			t.Errorf("deterministic=%v: IV is %d bytes, want %d", deterministic, len(iv), DirIVLen)
		}
		if keyIdx != 3 {
			t.Errorf("deterministic=%v: keyIdx = %d, want 3", deterministic, keyIdx)
		}
		if allZero := bytes.Equal(iv, allZeroDirIV); allZero != deterministic {
			t.Errorf("deterministic=%v: all-zero IV = %v", deterministic, allZero)
		}
	}
}

// The IV read from one mode must be rejected by the other: a random IV under
// -deterministic-names means the directory was written by a differently-configured filesystem,
// and an all-zero IV anywhere else is the corruption signal it has always been.
func TestDirIVModeMismatch(t *testing.T) {
	for _, wrote := range []bool{false, true} {
		dirfd, _ := openTestDir(t)
		if err := WriteDirIVAt(dirfd, 0, wrote); err != nil {
			t.Fatal(err)
		}
		n := newDirIVTestInstance(!wrote, 1)
		if _, _, err := n.ReadDirIVAt(dirfd); err == nil {
			t.Errorf("diriv written with deterministic=%v was accepted with deterministic=%v", wrote, !wrote)
		}
	}
}

// A 16-byte diriv is a pre-Phase-3 file with no index in it. It is an error, never "index absent,
// assume 0" — the whole point of the field is that nothing defaults.
func TestDirIVRejectsShortFile(t *testing.T) {
	n := newDirIVTestInstance(false, 1)
	dirfd, path := openTestDir(t)
	if err := os.WriteFile(path+"/"+DirIVFilename, cryptocore.RandBytes(DirIVLen), 0400); err != nil {
		t.Fatal(err)
	}
	if _, _, err := n.ReadDirIVAt(dirfd); err == nil {
		t.Error("a 16-byte diriv must be rejected")
	}
}

// Names encrypted under one ring index must not decrypt under another, and an index this mount
// has no key for must be an error rather than a panic or a wrong answer.
func TestNamesPerKeyIdx(t *testing.T) {
	n := newDirIVTestInstance(false, 2)
	iv := cryptocore.RandBytes(DirIVLen)

	c0, err := n.EncryptName("file", iv, 0)
	if err != nil {
		t.Fatal(err)
	}
	c1, err := n.EncryptName("file", iv, 1)
	if err != nil {
		t.Fatal(err)
	}
	if c0 == c1 {
		t.Fatal("the same name encrypted identically under two different keys")
	}
	if got, err := n.DecryptName(c1, iv, 1); err != nil || got != "file" {
		t.Errorf("DecryptName at index 1: got %q, err %v", got, err)
	}
	if _, err := n.DecryptName(c1, iv, 0); err == nil {
		t.Error("a name written under index 1 must not decrypt under index 0")
	}
	if _, err := n.EncryptName("file", iv, 2); err == nil {
		t.Error("an index the mount has no key for must be an error")
	}

	// Rotation installs the next key, then makes it the write key; neither step disturbs the
	// keys already there.
	if err := n.InstallCipher(2, newTestEMECipher(9)); err != nil {
		t.Fatal(err)
	}
	if got := n.WriteKeyIdx(); got != 1 {
		t.Errorf("WriteKeyIdx after InstallCipher = %d, want 1", got)
	}
	if err := n.SetWriteCipher(2); err != nil {
		t.Fatal(err)
	}
	if got := n.WriteKeyIdx(); got != 2 {
		t.Errorf("WriteKeyIdx = %d, want 2", got)
	}
	if got, err := n.DecryptName(c0, iv, 0); err != nil || got != "file" {
		t.Errorf("index 0 stopped working after a rotation: got %q, err %v", got, err)
	}
}

// Name keys arrive at explicit indices, in order, and the write key only moves forward onto a held
// key. Refused calls change nothing.
func TestInstallAndSetWriteCipher(t *testing.T) {
	n := newDirIVTestInstance(false, 2)
	c0 := n.emeCiphers.Load().ciphers[0]

	for _, idx := range []uint16{1, 3} {
		if err := n.InstallCipher(idx, newTestEMECipher(9)); err == nil {
			t.Errorf("InstallCipher(%d) with two keys held succeeded, want an error", idx)
		}
	}
	if c, err := n.emeCipher(0); err != nil || c != c0 {
		t.Errorf("index 0 after refused installs: got (%v, %v), want the original cipher", c, err)
	}
	if err := n.InstallCipher(2, nil); err != nil {
		t.Fatalf("installing a hole: %v", err)
	}
	c3 := newTestEMECipher(4)
	if err := n.InstallCipher(3, c3); err != nil {
		t.Fatal(err)
	}
	if _, err := n.emeCipher(2); !errors.Is(err, ErrKeyMissing) {
		t.Errorf("index 2 is a hole: got %v, want ErrKeyMissing", err)
	}
	if c, err := n.emeCipher(3); err != nil || c != c3 {
		t.Errorf("index 3: got (%v, %v), want the installed cipher", c, err)
	}
	if got := n.WriteKeyIdx(); got != 1 {
		t.Errorf("installs moved the write key to %d, want 1", got)
	}

	for _, tc := range []struct {
		idx  uint16
		what string
	}{{0, "backwards"}, {2, "a hole"}, {4, "out of range"}} {
		if err := n.SetWriteCipher(tc.idx); err == nil {
			t.Errorf("SetWriteCipher(%d), %s, succeeded", tc.idx, tc.what)
		}
	}
	if got := n.WriteKeyIdx(); got != 1 {
		t.Errorf("refused moves changed the write key to %d, want 1", got)
	}
	if err := n.SetWriteCipher(3); err != nil {
		t.Fatal(err)
	}
	if got := n.WriteKeyIdx(); got != 3 {
		t.Errorf("WriteKeyIdx = %d, want 3", got)
	}
}

// The learner is asked only for an index past the held prefix, holes included in that prefix. A
// learner that installs the key makes the lookup succeed; any other answer is ErrKeyMissing.
func TestNameKeyLearner(t *testing.T) {
	n := newDirIVTestInstance(false, 1)
	if err := n.InstallCipher(1, nil); err != nil {
		t.Fatal(err)
	}
	c2 := newTestEMECipher(3)
	var asked []uint16
	n.SetKeyLearner(func(keyIdx uint16) bool {
		asked = append(asked, keyIdx)
		switch keyIdx {
		case 2:
			return n.InstallCipher(2, c2) == nil
		case 9:
			// Claims success without installing anything.
			return true
		}
		return false
	})

	if _, err := n.emeCipher(0); err != nil {
		t.Errorf("index 0: %v", err)
	}
	if _, err := n.emeCipher(1); !errors.Is(err, ErrKeyMissing) {
		t.Errorf("hole at index 1: got %v, want ErrKeyMissing", err)
	}
	if len(asked) != 0 {
		t.Fatalf("held indices asked the learner for %v, want nothing", asked)
	}

	if c, err := n.emeCipher(2); err != nil || c != c2 {
		t.Errorf("index 2 via the learner: got (%v, %v), want the learned cipher", c, err)
	}
	if got := n.WriteKeyIdx(); got != 0 {
		t.Errorf("learning index 2 moved the write key to %d, want it at 0", got)
	}
	if _, err := n.emeCipher(2); err != nil {
		t.Errorf("index 2 once learned: %v", err)
	}
	if _, err := n.emeCipher(5); !errors.Is(err, ErrKeyMissing) {
		t.Errorf("index 5, not learned: got %v, want ErrKeyMissing", err)
	}
	if _, err := n.emeCipher(9); !errors.Is(err, ErrKeyMissing) {
		t.Errorf("index 9, learner claims success but installs nothing: got %v, want ErrKeyMissing", err)
	}
	if want := []uint16{2, 5, 9}; !slices.Equal(asked, want) {
		t.Errorf("learner was asked for %v, want %v", asked, want)
	}
}

// A lookup in a directory a sibling mount stamped with a newer index learns that index on the miss,
// and one it cannot learn surfaces ErrKeyMissing through DecryptName.
func TestDecryptNameLearnsSiblingKey(t *testing.T) {
	sibling := newDirIVTestInstance(false, 2)
	n := newDirIVTestInstance(false, 1)
	iv := cryptocore.RandBytes(DirIVLen)
	cName, err := sibling.EncryptName("file", iv, 1)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := n.DecryptName(cName, iv, 1); !errors.Is(err, ErrKeyMissing) {
		t.Errorf("without a learner: got %v, want ErrKeyMissing", err)
	}
	n.SetKeyLearner(func(keyIdx uint16) bool { return keyIdx == 1 && n.InstallCipher(1, newTestEMECipher(2)) == nil })
	if got, err := n.DecryptName(cName, iv, 1); err != nil || got != "file" {
		t.Errorf("with a learner: got %q, err %v", got, err)
	}
}

// DirIVRecord and CheckDirIVRecord are the publish and accept halves of the root diriv: the index
// survives in big-endian, and the all-zero rule holds in both directions.
func TestDirIVRecord(t *testing.T) {
	for _, deterministic := range []bool{false, true} {
		for _, idx := range []uint16{0, 1, 0x1234, 0xffff} {
			rec := DirIVRecord(idx, deterministic)
			if len(rec) != DirIVFileLen {
				t.Fatalf("deterministic=%v idx=%d: record is %d bytes, want %d", deterministic, idx, len(rec), DirIVFileLen)
			}
			if rec[DirIVLen] != byte(idx>>8) || rec[DirIVLen+1] != byte(idx) {
				t.Errorf("deterministic=%v idx=%d: index bytes %x, want big-endian", deterministic, idx, rec[DirIVLen:])
			}
			iv, got, err := CheckDirIVRecord(rec, deterministic)
			if err != nil {
				t.Fatalf("deterministic=%v idx=%d: %v", deterministic, idx, err)
			}
			if got != idx || len(iv) != DirIVLen {
				t.Errorf("deterministic=%v idx=%d: got index %d and a %d-byte IV", deterministic, idx, got, len(iv))
			}
			if allZero := bytes.Equal(iv, allZeroDirIV); allZero != deterministic {
				t.Errorf("deterministic=%v idx=%d: all-zero IV = %v", deterministic, idx, allZero)
			}
			if _, _, err := CheckDirIVRecord(rec, !deterministic); err == nil {
				t.Errorf("a record made with deterministic=%v was accepted with deterministic=%v", deterministic, !deterministic)
			}
		}
	}
	if bytes.Equal(DirIVRecord(0, false)[:DirIVLen], DirIVRecord(0, false)[:DirIVLen]) {
		t.Error("two random-IV records share an IV")
	}
}

// Anything but 18 bytes is refused, even when the IV part alone would pass.
func TestCheckDirIVRecordLength(t *testing.T) {
	for _, deterministic := range []bool{false, true} {
		for _, l := range []int{0, DirIVLen, DirIVFileLen - 1, DirIVFileLen + 1} {
			rec := make([]byte, l)
			if !deterministic {
				copy(rec, cryptocore.RandBytes(l))
			}
			if _, _, err := CheckDirIVRecord(rec, deterministic); err == nil {
				t.Errorf("deterministic=%v: a %d-byte record was accepted", deterministic, l)
			}
		}
	}
}

// The name side has the same wipe-while-serving shape as contentenc: a lookup that overlaps a wipe
// must get the old cipher or an error, never a torn snapshot. Run under -race.
func TestWipeConcurrent(t *testing.T) {
	n := newDirIVTestInstance(false, 2)
	var wg sync.WaitGroup
	start := make(chan struct{})
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			for range 200 {
				n.emeCipher(0)
			}
		}()
	}
	close(start)
	n.Wipe()
	wg.Wait()

	if _, err := n.emeCipher(0); !errors.Is(err, ErrKeyMissing) {
		t.Errorf("after a wipe every index must report a missing key: got %v", err)
	}
	if got := n.WriteKeyIdx(); got != 1 {
		t.Errorf("WriteKeyIdx after a wipe = %d, want 1", got)
	}
}
