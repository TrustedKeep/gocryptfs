package cryptocore

import (
	"bytes"
	"testing"
)

// "New" should accept at least these param combinations
func TestCryptoCoreNew(t *testing.T) {
	key := make([]byte, KeyLen)
	c := New(key, BackendGoGCM, 96)
	if c.IVLen != 12 {
		t.Fail()
	}
	c = New(key, BackendGoGCM, 128)
	if c.IVLen != 16 {
		t.Fail()
	}
}

// The EME (filename) key and the content key must both be derived, and must differ from each
// other and from the master key. Reusing the master key across EME's raw AES-ECB layer and GCM's
// AES-CTR keystream is the failure this derivation exists to prevent, so assert the keys are in
// fact distinct rather than trusting the call.
func TestCryptoCoreDerivesDistinctKeys(t *testing.T) {
	key := make([]byte, KeyLen)
	for i := range key {
		key[i] = byte(i)
	}
	emeKey := hkdfDerive(key, hkdfInfoEMENames, KeyLen)
	gcmKey := hkdfDerive(key, hkdfInfoGCMContent, KeyLen)
	if bytes.Equal(emeKey, gcmKey) {
		t.Error("EME and content keys are identical")
	}
	if bytes.Equal(emeKey, key) {
		t.Error("EME key equals the master key")
	}
	if bytes.Equal(gcmKey, key) {
		t.Error("content key equals the master key")
	}
}
