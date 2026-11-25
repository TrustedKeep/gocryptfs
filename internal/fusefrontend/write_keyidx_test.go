package fusefrontend

import (
	"bytes"
	"crypto/cipher"
	"encoding/binary"
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"

	"github.com/rfjakob/eme"

	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
)

// testCore builds a CryptoCore from a master key whose bytes are all "seed".
func testCore(seed byte) *cryptocore.CryptoCore {
	return cryptocore.New(bytes.Repeat([]byte{seed}, cryptocore.KeyLen), cryptocore.BackendGoGCM, contentenc.DefaultIVBits)
}

// testRootNode returns a root node whose content keys are "aeads", writing under the last.
func testRootNode(aeads ...cipher.AEAD) (*RootNode, *contentenc.ContentEnc) {
	cc := testCore(0)
	cEnc := contentenc.New(cc, aeads, contentenc.DefaultBS)
	return NewRootNode(Args{}, cEnc, nametransform.New([]*eme.EMECipher{cc.EMECipher}, true, 0, true, nil, false)), cEnc
}

// openTestFile opens the backing file "path" as a File of "rn".
func openTestFile(t *testing.T, rn *RootNode, path string) *File {
	t.Helper()
	fd, err := syscall.Open(path, syscall.O_RDWR|syscall.O_CREAT, 0600)
	if err != nil {
		t.Fatal(err)
	}
	f, _, errno := NewFile(fd, filepath.Base(path), rn)
	if errno != 0 {
		t.Fatal(errno)
	}
	t.Cleanup(func() { f.fd.Close() })
	return f
}

// blockKeyIdxs returns the key-ring index each ciphertext block of the backing file names.
func blockKeyIdxs(t *testing.T, cEnc *contentenc.ContentEnc, path string) (idxs []uint16) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	for off := cEnc.BlockNoToCipherOff(0); off < uint64(len(data)); off += cEnc.CipherBS() {
		idxs = append(idxs, binary.BigEndian.Uint16(data[off:]))
	}
	return idxs
}

// A write seals every block it touches under the write key, whatever key wrote the file before.
// After a rotation an append re-seals the partial last block and adds new ones under the new key,
// while blocks it does not touch keep theirs, so one file reads back across two keys.
func TestWritesUseTheWriteKey(t *testing.T) {
	bs := int(contentenc.DefaultBS)
	rn, cEnc := testRootNode(testCore(1).AEADCipher)
	path := filepath.Join(t.TempDir(), "file")
	f := openTestFile(t, rn, path)

	before := bytes.Repeat([]byte("a"), bs+10)
	if _, errno := f.doWrite(before, 0); errno != 0 {
		t.Fatal(errno)
	}
	cEnc.AddKey(testCore(2).AEADCipher)
	after := bytes.Repeat([]byte("b"), bs)
	if _, errno := f.doWrite(after, int64(len(before))); errno != 0 {
		t.Fatal(errno)
	}

	if got, want := blockKeyIdxs(t, cEnc, path), []uint16{0, 1, 1}; !slices.Equal(got, want) {
		t.Errorf("block key indexes = %v, want %v", got, want)
	}
	got, errno := f.doRead(nil, 0, uint64(3*bs))
	if errno != 0 {
		t.Fatal(errno)
	}
	if want := append(before, after...); !bytes.Equal(got, want) {
		t.Errorf("read back %d bytes, want %d matching bytes", len(got), len(want))
	}
}

// Over a block whose key this mount does not hold, a full-block write re-seals it under the write
// key, and a partial one fails with EIO at its read-modify-write instead of panicking.
func TestWriteOverABlockThisMountCannotRead(t *testing.T) {
	bs := int(contentenc.DefaultBS)
	path := filepath.Join(t.TempDir(), "file")
	rnA, _ := testRootNode(testCore(1).AEADCipher)
	if _, errno := openTestFile(t, rnA, path).doWrite(bytes.Repeat([]byte("a"), bs+10), 0); errno != 0 {
		t.Fatal(errno)
	}

	// Index 0 is not held, index 1 is the write key.
	rnB, cEncB := testRootNode(nil, testCore(2).AEADCipher)
	f := openTestFile(t, rnB, path)
	func() {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("partial write panicked: %v", r)
			}
		}()
		if _, errno := f.doWrite([]byte("x"), 10); errno != syscall.EIO {
			t.Errorf("partial write over an unreadable block: errno = %v, want EIO", errno)
		}
	}()
	full := bytes.Repeat([]byte("c"), bs)
	if _, errno := f.doWrite(full, 0); errno != 0 {
		t.Fatalf("full-block write over an unreadable block: %v", errno)
	}
	if got, want := blockKeyIdxs(t, cEncB, path), []uint16{1, 0}; !slices.Equal(got, want) {
		t.Errorf("block key indexes = %v, want %v", got, want)
	}
	if got, errno := f.doRead(nil, 0, uint64(bs)); errno != 0 || !bytes.Equal(got, full) {
		t.Errorf("re-sealed block: %d bytes, errno %v", len(got), errno)
	}
}
