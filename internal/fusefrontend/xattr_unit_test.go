package fusefrontend

// This file is named "xattr_unit_test.go" because there is also a
// "xattr_integration_test.go" in the test/xattr package.

import (
	"fmt"
	"testing"
	"time"

	"github.com/TrustedKeep/tkutils/v2/kem"
	"github.com/hanwen/go-fuse/v2/fs"

	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/internal/tkc"
)

func newTestFS(args Args) *RootNode {
	// Init crypto backend
	tkc.Connect("", "", true, true, false, "")
	id, kem, err := tkc.Get().CreateEnvelopeKey(kem.RSA2048.String(), "")
	if err != nil {
		fmt.Printf("couldnt create env key err: %v\n", err)
		return nil
	}

	_, wrapped, err := kem.Wrap()
	if err != nil {
		fmt.Printf("wrapping key err: %v\n", err)
		return nil
	}
	cCore := cryptocore.New(cryptocore.BackendGoGCM, contentenc.DefaultIVBits, 0, true, id, wrapped)
	cEnc := contentenc.New(cCore, contentenc.DefaultBS)
	n := nametransform.New(cCore.EMECipher, true, 0, true, nil, false)
	rn := NewRootNode(args, cEnc, n, id, wrapped)
	oneSecond := time.Second
	options := &fs.Options{
		EntryTimeout: &oneSecond,
		AttrTimeout:  &oneSecond,
	}
	fs.NewNodeFS(rn, options)
	return rn
}

func TestEncryptDecryptXattrName(t *testing.T) {
	fs := newTestFS(Args{})
	attr1 := "user.foo123456789"
	cAttr, err := fs.encryptXattrName(attr1)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("cAttr=%v", cAttr)
	attr2, err := fs.decryptXattrName(cAttr)
	if attr1 != attr2 || err != nil {
		t.Fatalf("Decrypt mismatch: %v != %v", attr1, attr2)
	}
}
