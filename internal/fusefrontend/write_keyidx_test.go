package fusefrontend

import (
	"crypto/cipher"
	"os"
	"path/filepath"
	"syscall"
	"testing"

	"github.com/rfjakob/eme"

	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
)

// A write to an existing file whose header names a key-ring index this mount cannot use fails with
// EIO, like a read of it. It must not reach the encrypt path, which panics and would take the whole
// mount down. A full-block write skips the read-modify-write that would otherwise fail first.
func TestWriteUnderAnUnusableKeyIsEIO(t *testing.T) {
	cCore := cryptocore.New(make([]byte, cryptocore.KeyLen), cryptocore.BackendGoGCM, contentenc.DefaultIVBits)
	// Index 0 is held, index 1 is a hole (its ring entry failed to unwrap), index 2 is past the ring.
	cEnc := contentenc.New(cCore, []cipher.AEAD{cCore.AEADCipher, nil}, contentenc.DefaultBS)
	n := nametransform.New([]*eme.EMECipher{cCore.EMECipher}, true, 0, true, nil, false)
	rn := NewRootNode(Args{}, cEnc, n)

	for _, keyIdx := range []uint16{1, 2} {
		path := filepath.Join(t.TempDir(), "file")
		// A header plus one byte, so the file is not read as empty and its header is kept.
		content := append(contentenc.RandomHeader(keyIdx).Pack(), 0)
		if err := os.WriteFile(path, content, 0600); err != nil {
			t.Fatal(err)
		}
		fd, err := syscall.Open(path, syscall.O_RDWR, 0)
		if err != nil {
			t.Fatal(err)
		}
		f, _, errno := NewFile(fd, "file", rn)
		if errno != 0 {
			t.Fatal(errno)
		}
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("key index %d: write panicked: %v", keyIdx, r)
				}
			}()
			if _, errno = f.doWrite(make([]byte, contentenc.DefaultBS), 0); errno != syscall.EIO {
				t.Errorf("key index %d: errno = %v, want EIO", keyIdx, errno)
			}
		}()
		f.fd.Close()
	}
}
