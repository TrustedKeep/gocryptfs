package cryptocore

import (
	"bytes"
	"testing"
)

// Every backend must prepend its own random nonce, and New must refuse any other IV length.
func TestCryptoCoreNew(t *testing.T) {
	key := make([]byte, KeyLen)
	for _, b := range []AEADTypeEnum{BackendGoGCM, BackendXChaCha20Poly1305} {
		c := New(key, b, b.NonceSize*8)
		if c.IVLen != b.NonceSize || c.AEADCipher.NonceSize() != 0 || c.AEADCipher.Overhead() != b.NonceSize+AuthTagLen {
			t.Errorf("%s: IVLen=%d NonceSize=%d Overhead=%d", b, c.IVLen, c.AEADCipher.NonceSize(), c.AEADCipher.Overhead())
		}
		ad := []byte("ad")
		ct1 := c.AEADCipher.Seal(nil, nil, []byte("x"), ad)
		ct2 := c.AEADCipher.Seal(nil, nil, []byte("x"), ad)
		if bytes.Equal(ct1[:b.NonceSize], ct2[:b.NonceSize]) {
			t.Errorf("%s: two seals drew the same nonce", b)
		}
		if pt, err := c.AEADCipher.Open(nil, nil, ct1, ad); err != nil || string(pt) != "x" {
			t.Errorf("%s: Open = %q, %v", b, pt, err)
		}
		if _, err := c.AEADCipher.Open(nil, nil, ct1[:b.NonceSize+AuthTagLen-1], ad); err == nil {
			t.Errorf("%s: Open accepted a truncated ciphertext", b)
		}
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("New accepted 128-bit GCM IVs")
			}
		}()
		New(key, BackendGoGCM, 128)
	}()
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
	c1 := New(k1, BackendGoGCM, 96)
	c2 := New(k2, BackendGoGCM, 96)
	if _, err := c2.AEADCipher.Open(nil, nil, c1.AEADCipher.Seal(nil, nil, []byte("x"), nil), nil); err == nil {
		t.Error("one core opened the other's ciphertext")
	}
}
