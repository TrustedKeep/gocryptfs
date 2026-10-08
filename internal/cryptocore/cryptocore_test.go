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

// Two key-ring entries must produce genuinely independent cores. If a rotation derived the same
// keys as the entry it replaced, the whole exercise would be a no-op that still looked correct
// everywhere else, since every index would keep decrypting.
func TestCryptoCoreDistinctPerEntry(t *testing.T) {
	k1 := make([]byte, KeyLen)
	k2 := make([]byte, KeyLen)
	for i := range k2 {
		k2[i] = byte(i + 1)
	}
	if bytes.Equal(hkdfDerive(k1, hkdfInfoEMENames, KeyLen), hkdfDerive(k2, hkdfInfoEMENames, KeyLen)) {
		t.Error("two master keys derived the same EME key")
	}
	if bytes.Equal(hkdfDerive(k1, hkdfInfoGCMContent, KeyLen), hkdfDerive(k2, hkdfInfoGCMContent, KeyLen)) {
		t.Error("two master keys derived the same content key")
	}
	c1 := New(k1, BackendGoGCM, 128)
	c2 := New(k2, BackendGoGCM, 128)
	nonce := make([]byte, c1.IVLen)
	nonce[0] = 1
	if bytes.Equal(c1.AEADCipher.Seal(nil, nonce, []byte("x"), nil), c2.AEADCipher.Seal(nil, nonce, []byte("x"), nil)) {
		t.Error("two cores encrypt identically")
	}
}

// N cores must share one nonce source per length. A generator per core would park a goroutine
// holding 500 pre-generated nonces for every key that is never written under.
func TestNonceGeneratorMemoized(t *testing.T) {
	if newNonceGenerator(16) != newNonceGenerator(16) {
		t.Error("same nonce length handed out two generators")
	}
	if newNonceGenerator(16) == newNonceGenerator(24) {
		t.Error("different nonce lengths share a generator")
	}
	if n := len(newNonceGenerator(24).Get()); n != 24 {
		t.Errorf("nonce length = %d, want 24", n)
	}
}
