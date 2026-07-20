package tkc

import (
	"bytes"
	"path/filepath"
	"testing"
)

func newTestGateway(t *testing.T, nodeID string) *mockGatewayConnector {
	t.Helper()
	gw := newMockGatewayConnector(nodeID, filepath.Join(t.TempDir(), "gw.db"))
	t.Cleanup(func() { gw.Close() })
	return gw
}

func TestMockGatewayGenerateUnwrap(t *testing.T) {
	gw := newTestGateway(t, "node-A")

	dk, err := gw.GenerateDataKey()
	if err != nil {
		t.Fatalf("GenerateDataKey: %v", err)
	}
	if dk.KeyID == "" {
		t.Error("empty KeyID")
	}
	if len(dk.Plaintext) != dataKeyLength {
		t.Errorf("plaintext length = %d, want %d", len(dk.Plaintext), dataKeyLength)
	}
	if len(dk.Ciphertext) == 0 {
		t.Error("empty Ciphertext")
	}
	if bytes.Equal(dk.Plaintext, dk.Ciphertext) {
		t.Error("ciphertext must not equal plaintext")
	}

	pt, err := gw.UnwrapDataKey(dk.KeyID, dk.Ciphertext)
	if err != nil {
		t.Fatalf("UnwrapDataKey: %v", err)
	}
	if !bytes.Equal(pt, dk.Plaintext) {
		t.Error("unwrapped key does not match generated plaintext")
	}
}

// Generating a second key (how rotation is performed) must not invalidate the first: both
// keys still unwrap, so data written under the old key stays readable.
func TestMockGatewayRegenerateRetainsOldKeys(t *testing.T) {
	gw := newTestGateway(t, "node-A")

	k1, err := gw.GenerateDataKey()
	if err != nil {
		t.Fatalf("GenerateDataKey (first): %v", err)
	}
	k2, err := gw.GenerateDataKey()
	if err != nil {
		t.Fatalf("GenerateDataKey (second): %v", err)
	}
	if k1.KeyID == k2.KeyID {
		t.Error("second generate produced the same KeyID")
	}
	if bytes.Equal(k1.Plaintext, k2.Plaintext) {
		t.Error("second generate produced the same plaintext key")
	}

	// Both the old and the new key must still unwrap (old data stays readable).
	for _, dk := range []DataKey{k1, k2} {
		pt, err := gw.UnwrapDataKey(dk.KeyID, dk.Ciphertext)
		if err != nil {
			t.Fatalf("UnwrapDataKey(%s): %v", dk.KeyID, err)
		}
		if !bytes.Equal(pt, dk.Plaintext) {
			t.Errorf("unwrapped key %s does not match", dk.KeyID)
		}
	}
}

// The mock persists KEKs so a fresh connector on the same store (simulating -init then a
// later mount) can still unwrap a ciphertext generated earlier.
func TestMockGatewayPersistsAcrossReopen(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "gw.db")

	gw1 := newMockGatewayConnector("node-A", dbPath)
	dk, err := gw1.GenerateDataKey()
	if err != nil {
		t.Fatalf("GenerateDataKey: %v", err)
	}
	if err := gw1.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	gw2 := newMockGatewayConnector("node-A", dbPath)
	defer gw2.Close()
	pt, err := gw2.UnwrapDataKey(dk.KeyID, dk.Ciphertext)
	if err != nil {
		t.Fatalf("UnwrapDataKey after reopen: %v", err)
	}
	if !bytes.Equal(pt, dk.Plaintext) {
		t.Error("unwrapped key after reopen does not match")
	}
}

// keyspace = NodeID isolates filesystems: another node cannot unwrap a key it did not own,
// even sharing the same mock store.
func TestMockGatewayKeyspaceIsolation(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "gw.db")

	gwA := newMockGatewayConnector("node-A", dbPath)
	dk, err := gwA.GenerateDataKey()
	if err != nil {
		t.Fatalf("GenerateDataKey: %v", err)
	}
	if err := gwA.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}

	gwB := newMockGatewayConnector("node-B", dbPath)
	defer gwB.Close()
	if _, err := gwB.UnwrapDataKey(dk.KeyID, dk.Ciphertext); err == nil {
		t.Error("node-B unwrapped node-A's key across keyspaces")
	}
}

func TestMockGatewayUnknownKey(t *testing.T) {
	gw := newTestGateway(t, "node-A")
	if _, err := gw.UnwrapDataKey("does-not-exist", []byte("whatever")); err == nil {
		t.Error("expected error unwrapping an unknown key ID")
	}
}

// A valid KeyID with a corrupted ciphertext must be rejected by the AEAD integrity check,
// not silently returned as bogus plaintext.
func TestMockGatewayRejectsTamperedCiphertext(t *testing.T) {
	gw := newTestGateway(t, "node-A")
	dk, err := gw.GenerateDataKey()
	if err != nil {
		t.Fatalf("GenerateDataKey: %v", err)
	}
	corrupt := make([]byte, len(dk.Ciphertext))
	copy(corrupt, dk.Ciphertext)
	corrupt[len(corrupt)-1] ^= 0x01 // flip a bit in the GCM tag
	if _, err := gw.UnwrapDataKey(dk.KeyID, corrupt); err == nil {
		t.Error("expected error unwrapping a tampered ciphertext under a valid key ID")
	}
}
