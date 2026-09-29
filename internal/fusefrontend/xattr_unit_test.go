package fusefrontend

// This file is named "xattr_unit_test.go" because there is also a
// "xattr_integration_test.go" in the test/xattr package.

import (
	"crypto/cipher"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"github.com/rfjakob/eme"

	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
)

func newTestFS(args Args) *RootNode {
	// Init crypto backend from an all-zero master key.
	cCore := cryptocore.New(make([]byte, cryptocore.KeyLen), cryptocore.BackendGoGCM, contentenc.DefaultIVBits)
	cEnc := contentenc.New(cCore, []cipher.AEAD{cCore.AEADCipher}, contentenc.DefaultBS)
	n := nametransform.New([]*eme.EMECipher{cCore.EMECipher}, true, 0, true, nil, false)
	rn := NewRootNode(args, cEnc, n)
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
	cAttr, err := fs.encryptXattrName(attr1, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("cAttr=%v", cAttr)
	attr2, err := fs.decryptXattrName(cAttr, 0)
	if attr1 != attr2 || err != nil {
		t.Fatalf("Decrypt mismatch: %v != %v", attr1, attr2)
	}
}

func TestParseXattrKeyIdx(t *testing.T) {
	for _, tc := range []struct {
		names  []string
		idx    uint16
		ok     bool
		errors bool
	}{
		{names: nil},
		{names: []string{"user.gocryptfs.abc", "security.selinux"}},
		{names: []string{"user.gocryptfs.abc", xattrKeyIdxPrefix + "3"}, idx: 3, ok: true},
		{names: []string{xattrKeyIdxPrefix + "1", xattrKeyIdxPrefix + "2"}, errors: true},
		{names: []string{xattrKeyIdxPrefix + "x"}, errors: true},
		{names: []string{xattrKeyIdxPrefix + "65536"}, errors: true},
	} {
		idx, ok, err := parseXattrKeyIdx(tc.names)
		if (err != nil) != tc.errors || idx != tc.idx || ok != tc.ok {
			t.Errorf("%v: got (%d, %v, %v), want (%d, %v, error=%v)", tc.names, idx, ok, err, tc.idx, tc.ok, tc.errors)
		}
	}
}
