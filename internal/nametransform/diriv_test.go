package nametransform

import (
	"bytes"
	"os"
	"sync"
	"syscall"
	"testing"

	"github.com/rfjakob/eme"

	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
)

func newDirIVTestInstance(deterministicNames bool, keys int) *NameTransform {
	ciphers := make([]*eme.EMECipher, keys)
	for i := range ciphers {
		key := make([]byte, cryptocore.KeyLen)
		key[0] = byte(i + 1)
		ciphers[i] = cryptocore.New(key, cryptocore.BackendGoGCM, contentenc.DefaultIVBits).EMECipher
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

	// AddCipher is rotation's entry point: it must become the write key without disturbing
	// the ones already there.
	key := make([]byte, cryptocore.KeyLen)
	key[0] = 9
	if got := n.AddCipher(cryptocore.New(key, cryptocore.BackendGoGCM, contentenc.DefaultIVBits).EMECipher); got != 2 {
		t.Errorf("AddCipher returned %d, want 2", got)
	}
	if got := n.WriteKeyIdx(); got != 2 {
		t.Errorf("WriteKeyIdx = %d, want 2", got)
	}
	if got, err := n.DecryptName(c0, iv, 0); err != nil || got != "file" {
		t.Errorf("index 0 stopped working after AddCipher: got %q, err %v", got, err)
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

	if _, err := n.emeCipher(0); err == nil {
		t.Error("after a wipe every index must report a missing key")
	}
}
