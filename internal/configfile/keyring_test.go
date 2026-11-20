package configfile

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
)

func confPath(dir string) string { return filepath.Join(dir, ConfDefaultName) }

func testKeyRing(dir string) *KeyRing {
	return &KeyRing{
		filename: keyRingPath(confPath(dir)),
		Keys: []KeyRingEntry{
			{KeyID: "kek", Ciphertext: []byte{1, 2, 3, 4}, CreatedAt: time.Unix(1000, 0).UTC()},
			{KeyID: "kek", Ciphertext: []byte{5, 6, 7, 8}, CreatedAt: time.Unix(2000, 0).UTC(), OpCount: 42},
		},
	}
}

// The ring sits next to the config, whatever the config is named.
func TestKeyRingPath(t *testing.T) {
	if got, want := keyRingPath("/a/b/gocryptfs.conf"), "/a/b/"+KeyRingFileName; got != want {
		t.Errorf("keyRingPath = %q, want %q", got, want)
	}
	if got, want := keyRingPath("/a/b/custom.conf"), "/a/b/"+KeyRingFileName; got != want {
		t.Errorf("keyRingPath = %q, want %q", got, want)
	}
}

// Active is the newest entry, and an empty ring has none.
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
	kr.Keys = append(kr.Keys, KeyRingEntry{KeyID: "k1", Ciphertext: []byte{3, 4}})
	if e, err = kr.Active(); err != nil {
		t.Fatalf("two-entry ring: %v", err)
	}
	if !bytes.Equal(e.Ciphertext, []byte{3, 4}) {
		t.Errorf("Ciphertext = %v, want the newest entry's {3 4}", e.Ciphertext)
	}
	if got, err := kr.ActiveIdx(); err != nil || got != 1 {
		t.Errorf("ActiveIdx = %d, %v, want 1, nil", got, err)
	}
	if _, err := (&KeyRing{}).ActiveIdx(); err == nil {
		t.Error("empty ring must have no active index")
	}
}

// Every entry needs a KeyID and a Ciphertext, and a ring names one KEK.
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
	kr.Keys = []KeyRingEntry{
		{KeyID: "kek-1", Ciphertext: []byte{1}},
		{KeyID: "kek-1", Ciphertext: []byte{2}},
	}
	if err := kr.Validate(); err != nil {
		t.Errorf("a ring naming one KEK should validate: %v", err)
	}
	kr.Keys[1].KeyID = "kek-2"
	if err := kr.Validate(); err == nil {
		t.Error("a ring whose entries name two different KEKs must be rejected")
	}
}

// An entry's index is a uint16, so a ring holds at most 1<<16 entries: Append refuses another and
// Validate refuses a ring that somehow has one.
func TestKeyRingBoundedByUint16(t *testing.T) {
	e := KeyRingEntry{KeyID: "kek", Ciphertext: []byte{1}}
	kr := &KeyRing{Keys: make([]KeyRingEntry, 1<<16)}
	for i := range kr.Keys {
		kr.Keys[i] = e
	}
	if err := kr.Validate(); err != nil {
		t.Fatalf("a full ring must validate: %v", err)
	}
	if _, err := kr.Append(e); !errors.Is(err, ErrKeyRingFull) {
		t.Fatalf("Append to a full ring: err = %v, want ErrKeyRingFull", err)
	}
	if len(kr.Keys) != 1<<16 {
		t.Errorf("a refused Append grew the ring to %d entries", len(kr.Keys))
	}
	kr.Keys = append(kr.Keys, e)
	if err := kr.Validate(); err == nil {
		t.Error("a ring past 1<<16 entries must not validate")
	}
}

// An entry's ring index is its position: Append hands out the next one and ActiveIdx names the last.
func TestKeyRingAppend(t *testing.T) {
	kr := &KeyRing{}
	for want := uint16(0); want < 3; want++ {
		got, err := kr.Append(KeyRingEntry{KeyID: "kek", Ciphertext: []byte{byte(want)}})
		if err != nil || got != want {
			t.Errorf("Append returned %d, %v, want %d", got, err, want)
		}
	}
	if err := kr.Validate(); err != nil {
		t.Errorf("appended ring should validate: %v", err)
	}
	if len(kr.All()) != 3 {
		t.Errorf("All() has %d entries, want 3", len(kr.All()))
	}
	idx, err := kr.ActiveIdx()
	if err != nil {
		t.Fatal(err)
	}
	if idx != 2 {
		t.Errorf("ActiveIdx = %d, want 2", idx)
	}
	active, err := kr.Active()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(active.Ciphertext, kr.All()[idx].Ciphertext) {
		t.Error("Active() and All()[ActiveIdx()] must be the same entry")
	}
}

// The ring round-trips through disk, ciphertext base64-encoded.
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
	// Rewriting an existing ring must not trip over the exclusive tmp create.
	if err := kr.WriteFile(); err != nil {
		t.Errorf("second WriteFile: %v", err)
	}
}

// An absent ring is a fresh filesystem. A zero-length one is a truncated write, and treating it as
// fresh would generate a key over existing data.
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

// A malformed entry fails at load with LoadConf; without the code, exitcodes.Exit reports Other.
func TestLoadKeyRingRejectsMalformed(t *testing.T) {
	dir := t.TempDir()
	js, err := json.Marshal(&KeyRing{Keys: []KeyRingEntry{{KeyID: "k1"}}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyRingPath(confPath(dir)), js, 0400); err != nil {
		t.Fatal(err)
	}
	_, err = LoadKeyRing(confPath(dir))
	if err == nil {
		t.Fatal("entry with no Ciphertext should be rejected at load")
	}
	coded, ok := err.(exitcodes.Err)
	if !ok {
		t.Fatalf("error must carry an exit code, got %T", err)
	}
	if coded.Code() != exitcodes.LoadConf {
		t.Errorf("exit code = %d, want %d (LoadConf)", coded.Code(), exitcodes.LoadConf)
	}
}

// Only the active entry is credited, and a zero delta reports no change so an idle mount skips the
// rewrite.
func TestAddOpCount(t *testing.T) {
	kr := &KeyRing{Keys: []KeyRingEntry{
		{KeyID: "kek", Ciphertext: []byte("c"), OpCount: 10},
		{KeyID: "kek", Ciphertext: []byte("c"), OpCount: 3},
	}}
	if kr.AddOpCount(0) {
		t.Error("a zero delta must not report a change")
	}
	if !kr.AddOpCount(7) {
		t.Error("a non-zero delta must report a change")
	}
	if kr.Keys[1].OpCount != 10 {
		t.Errorf("active count = %d, want 10", kr.Keys[1].OpCount)
	}
	if kr.Keys[0].OpCount != 10 {
		t.Errorf("superseded count = %d, want it untouched at 10", kr.Keys[0].OpCount)
	}
	if (&KeyRing{}).AddOpCount(5) {
		t.Error("an empty ring has nothing to credit")
	}
}

// The one-KEK rule also holds at load, with LoadConf.
func TestLoadKeyRingRejectsTwoKEKs(t *testing.T) {
	dir := t.TempDir()
	js, err := json.Marshal(&KeyRing{Keys: []KeyRingEntry{
		{KeyID: "kek-1", Ciphertext: []byte{1}},
		{KeyID: "kek-2", Ciphertext: []byte{2}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyRingPath(confPath(dir)), js, 0400); err != nil {
		t.Fatal(err)
	}
	_, err = LoadKeyRing(confPath(dir))
	if err == nil {
		t.Fatal("a ring naming two KEKs should be rejected at load")
	}
	coded, ok := err.(exitcodes.Err)
	if !ok || coded.Code() != exitcodes.LoadConf {
		t.Errorf("error = %v (%T), want one carrying LoadConf", err, err)
	}
}

// The instance's identity is the entries' KeyID, and an empty ring has none.
func TestKeyRingKekIDIsTheKeyID(t *testing.T) {
	if got := (&KeyRing{}).KekID(); got != "" {
		t.Errorf("empty ring: identity = %q, want \"\"", got)
	}

	kr := &KeyRing{}
	const keyID = "kek-instance"
	for i := 0; i < 3; i++ {
		kr.Append(KeyRingEntry{KeyID: keyID, Ciphertext: []byte{byte(i)}})
	}
	if got := kr.KekID(); got != keyID {
		t.Errorf("identity = %q, want %q", got, keyID)
	}
}

// flock conflicts between open file descriptions, so two opens in one process stand in for two mounts.
func TestLockKeyRing(t *testing.T) {
	dir := t.TempDir()
	first, err := LockKeyRing(confPath(dir), 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := LockKeyRing(confPath(dir), 0); !errors.Is(err, ErrKeyRingInUse) {
		t.Fatalf("second lock: err = %v, want ErrKeyRingInUse", err)
	}
	// A holder that lets go within the wait, as an exiting mount does, is waited out.
	go func() {
		time.Sleep(100 * time.Millisecond)
		first.Close()
	}()
	again, err := LockKeyRing(confPath(dir), 5*time.Second)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	again.Close()
}
