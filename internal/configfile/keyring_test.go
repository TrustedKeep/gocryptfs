package configfile

import (
	"bytes"
	"encoding/json"
	"path/filepath"
	"testing"
	"time"

	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
)

func gatewayKEKConf() *ConfFile {
	return &ConfFile{
		Version: contentenc.CurrentVersion,
		FeatureFlags: []string{
			knownFlags[FlagGCMIV128], knownFlags[FlagHKDF], knownFlags[FlagGatewayKEK],
		},
		NodeID: "node-1",
		KeyRing: []KeyRingEntry{
			{KeyID: "k1", Ciphertext: []byte{1, 2, 3, 4}, CreatedAt: time.Unix(1000, 0).UTC()},
			{KeyID: "k2", Ciphertext: []byte{5, 6, 7, 8}, CreatedAt: time.Unix(2000, 0).UTC(), OpCount: 42},
		},
	}
}

func TestGatewayKEKFlagIsKnown(t *testing.T) {
	if !isFeatureFlagKnown("GatewayKEK") {
		t.Error("GatewayKEK feature flag should be known")
	}
}

// A config carrying the GatewayKEK flag and a populated key ring must validate and survive
// a JSON round-trip unchanged (ciphertext base64-encoded, timestamps and op counts intact).
func TestKeyRingRoundTrip(t *testing.T) {
	cf := gatewayKEKConf()
	if err := cf.Validate(); err != nil {
		t.Fatalf("Validate: %v", err)
	}

	js, err := json.Marshal(cf)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	// []byte ciphertext is base64-encoded in JSON: {1,2,3,4} -> "AQIDBA==".
	if !bytes.Contains(js, []byte("AQIDBA==")) {
		t.Error("ciphertext {1,2,3,4} should appear base64-encoded (AQIDBA==) in JSON")
	}

	var got ConfFile
	if err := json.Unmarshal(js, &got); err != nil {
		t.Fatalf("Unmarshal: %v", err)
	}
	if len(got.KeyRing) != len(cf.KeyRing) {
		t.Fatalf("KeyRing length = %d, want %d", len(got.KeyRing), len(cf.KeyRing))
	}
	for i, want := range cf.KeyRing {
		g := got.KeyRing[i]
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
}

// A config with no key ring must serialize without the KeyRing field (omitempty), so
// existing configs are byte-for-byte unaffected by the new schema.
func TestKeyRingOmittedWhenEmpty(t *testing.T) {
	cf := &ConfFile{
		Version:      contentenc.CurrentVersion,
		FeatureFlags: []string{knownFlags[FlagGCMIV128], knownFlags[FlagHKDF]},
		NodeID:       "node-1",
	}
	js, err := json.Marshal(cf)
	if err != nil {
		t.Fatalf("Marshal: %v", err)
	}
	if bytes.Contains(js, []byte("KeyRing")) {
		t.Error("empty KeyRing should be omitted from JSON")
	}
}

// WriteFile/Load must preserve the key ring on disk.
func TestKeyRingWriteLoad(t *testing.T) {
	cf := gatewayKEKConf()
	cf.filename = filepath.Join(t.TempDir(), "gocryptfs.conf")
	if err := cf.WriteFile(); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}
	loaded, err := Load(cf.filename)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if len(loaded.KeyRing) != 2 || loaded.KeyRing[1].OpCount != 42 {
		t.Errorf("key ring not preserved on disk: %+v", loaded.KeyRing)
	}
}
