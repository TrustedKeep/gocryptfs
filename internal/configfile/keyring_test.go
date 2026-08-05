package configfile

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// confPath is the config path a test filesystem in "dir" would have. LoadKeyRing takes this,
// not the ring path, and derives the ring location itself.
func confPath(dir string) string { return filepath.Join(dir, ConfDefaultName) }

func testKeyRing(dir string) *KeyRing {
	return &KeyRing{
		filename: keyRingPath(confPath(dir)),
		Keys: []KeyRingEntry{
			{KeyID: "k1", Ciphertext: []byte{1, 2, 3, 4}, CreatedAt: time.Unix(1000, 0).UTC()},
			{KeyID: "k2", Ciphertext: []byte{5, 6, 7, 8}, CreatedAt: time.Unix(2000, 0).UTC(), OpCount: 42},
		},
	}
}

// The ring must resolve next to the config file, whatever the config is named, so a custom
// -config path keeps its key ring beside it rather than in the cipherdir root.
func TestKeyRingPath(t *testing.T) {
	if got, want := keyRingPath("/a/b/gocryptfs.conf"), "/a/b/"+KeyRingFileName; got != want {
		t.Errorf("keyRingPath = %q, want %q", got, want)
	}
	if got, want := keyRingPath("/a/b/custom.conf"), "/a/b/"+KeyRingFileName; got != want {
		t.Errorf("keyRingPath = %q, want %q", got, want)
	}
}

// Active must return the NEWEST entry, not the first. Phase 2 only ever writes one, so the
// distinction is invisible today; pinning it now means appending a rotated key in Phase 3 cannot
// silently keep encrypting under the old one. An empty ring has no active key and must error
// rather than index out of range.
func TestActive(t *testing.T) {
	kr := &KeyRing{}
	if _, err := kr.Active(); err == nil {
		t.Error("empty ring must be rejected")
	}
	kr.Keys = []KeyRingEntry{{KeyID: "k1", Ciphertext: []byte{1, 2}}}
	e, err := kr.Active()
	if err != nil {
		t.Fatalf("single-entry ring: %v", err)
	}
	if e.KeyID != "k1" {
		t.Errorf("KeyID = %q, want k1", e.KeyID)
	}
	kr.Keys = append(kr.Keys, KeyRingEntry{KeyID: "k2", Ciphertext: []byte{3, 4}})
	if e, err = kr.Active(); err != nil {
		t.Fatalf("two-entry ring: %v", err)
	}
	if e.KeyID != "k2" {
		t.Errorf("KeyID = %q, want k2 (the newest entry)", e.KeyID)
	}
}

// An entry that cannot be recovered (no KeyID or no Ciphertext) must be rejected rather than
// carried into the mount, where it would fail later and less clearly.
func TestKeyRingValidate(t *testing.T) {
	kr := &KeyRing{}
	if err := kr.Validate(); err != nil {
		t.Errorf("empty ring should validate (freshly initialized fs): %v", err)
	}
	kr.Keys = []KeyRingEntry{{KeyID: "", Ciphertext: []byte{1}}}
	if err := kr.Validate(); err == nil {
		t.Error("entry with empty KeyID should be rejected")
	}
	kr.Keys = []KeyRingEntry{{KeyID: "k1"}}
	if err := kr.Validate(); err == nil {
		t.Error("entry with empty Ciphertext should be rejected")
	}
}

// WriteFile/LoadKeyRing must round-trip the ring on disk with ciphertext base64-encoded and
// timestamps and op counts intact.
func TestKeyRingWriteLoad(t *testing.T) {
	dir := t.TempDir()
	kr := testKeyRing(dir)
	if err := kr.WriteFile(); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	js, err := os.ReadFile(kr.filename)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}
	// []byte ciphertext is base64-encoded in JSON: {1,2,3,4} -> "AQIDBA==".
	if !bytes.Contains(js, []byte("AQIDBA==")) {
		t.Error("ciphertext {1,2,3,4} should appear base64-encoded (AQIDBA==) in JSON")
	}

	loaded, err := LoadKeyRing(confPath(dir))
	if err != nil {
		t.Fatalf("LoadKeyRing: %v", err)
	}
	if len(loaded.Keys) != len(kr.Keys) {
		t.Fatalf("Keys length = %d, want %d", len(loaded.Keys), len(kr.Keys))
	}
	for i, want := range kr.Keys {
		g := loaded.Keys[i]
		if g.KeyID != want.KeyID {
			t.Errorf("entry %d KeyID = %q, want %q", i, g.KeyID, want.KeyID)
		}
		if !bytes.Equal(g.Ciphertext, want.Ciphertext) {
			t.Errorf("entry %d Ciphertext = %v, want %v", i, g.Ciphertext, want.Ciphertext)
		}
		if !g.CreatedAt.Equal(want.CreatedAt) {
			t.Errorf("entry %d CreatedAt = %v, want %v", i, g.CreatedAt, want.CreatedAt)
		}
		if g.OpCount != want.OpCount {
			t.Errorf("entry %d OpCount = %d, want %d", i, g.OpCount, want.OpCount)
		}
	}
	// Writing again over an existing ring must succeed: rotation (Phase 3) rewrites this file,
	// and the exclusive tmp create must not leave a blocker behind.
	if err := kr.WriteFile(); err != nil {
		t.Errorf("second WriteFile: %v", err)
	}
}

// An absent file is the freshly-initialized state and must load as an empty ring; a zero-length
// file is a truncated write and must NOT, since treating it as fresh would regenerate the key
// over existing data.
func TestLoadKeyRingAbsentVsEmpty(t *testing.T) {
	dir := t.TempDir()
	path := keyRingPath(confPath(dir))

	kr, err := LoadKeyRing(confPath(dir))
	if err != nil {
		t.Fatalf("absent key ring should load as empty: %v", err)
	}
	if len(kr.Keys) != 0 {
		t.Errorf("absent key ring has %d entries, want 0", len(kr.Keys))
	}
	// WriteFile on the ring returned for an absent file must land at the right path.
	kr.Keys = []KeyRingEntry{{KeyID: "k1", Ciphertext: []byte{9}}}
	if err := kr.WriteFile(); err != nil {
		t.Fatalf("WriteFile after loading an absent ring: %v", err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Errorf("ring was not written to %q: %v", path, err)
	}

	// The ring we just wrote is 0400, so replace it rather than opening it for writing.
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, nil, 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyRing(confPath(dir)); err == nil {
		t.Error("zero-length key ring must be rejected, not treated as a fresh filesystem")
	}
}

// A malformed entry on disk must be caught at load, not at first use.
func TestLoadKeyRingRejectsMalformed(t *testing.T) {
	dir := t.TempDir()
	js, err := json.Marshal(&KeyRing{Keys: []KeyRingEntry{{KeyID: "k1"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyRingPath(confPath(dir)), js, 0400); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadKeyRing(confPath(dir)); err == nil {
		t.Error("entry with no Ciphertext should be rejected at load")
	}
}
