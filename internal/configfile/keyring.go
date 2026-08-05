package configfile

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
)

// KeyRingFileName is the name of the file that holds the key ring, next to gocryptfs.conf.
//
// The key material lives here rather than in gocryptfs.conf so that the config stays a
// static, human-editable description of the filesystem that no mount ever rewrites, and the
// one file that does get rewritten (on first mount, and on rotation in Phase 3) holds nothing
// but ciphertext.
const KeyRingFileName = "KR"

// KeyRingEntry is one gateway-wrapped master key.
type KeyRingEntry struct {
	// KeyID identifies the gateway wrapping-key generation, passed back on unwrap.
	KeyID string
	// Ciphertext is the gateway-wrapped master key (base64-encoded in JSON).
	Ciphertext []byte
	// CreatedAt records when this key was appended to the ring.
	CreatedAt time.Time
	// OpCount is the persisted per-key encrypt-op counter that drives auto-rotation.
	OpCount uint64 `json:",omitempty"`
}

// KeyRing is the on-disk key ring. Ciphertext only — the plaintext keys are unwrapped at
// mount and held in memory. Ordered; the newest entry is the active write key.
type KeyRing struct {
	Keys []KeyRingEntry
	// filename is the path this ring was loaded from / will be written to. Not exported to JSON.
	filename string
}

// keyRingPath derives the key-ring path from the config path. There is exactly one possible
// location — next to gocryptfs.conf — so callers pass the config path they already have and
// cannot name a ring belonging to some other filesystem.
func keyRingPath(confPath string) string {
	return filepath.Join(filepath.Dir(confPath), KeyRingFileName)
}

// LoadKeyRing loads the key ring belonging to the config file at "confPath". A missing ring is
// not an error: it is the freshly-initialized state, and yields an empty ring the first mount
// will populate.
func LoadKeyRing(confPath string) (*KeyRing, error) {
	filename := keyRingPath(confPath)
	kr := &KeyRing{filename: filename}
	js, err := os.ReadFile(filename)
	if os.IsNotExist(err) {
		return kr, nil
	}
	if err != nil {
		return nil, exitcodes.NewErr(err.Error(), exitcodes.OpenConf)
	}
	if len(js) == 0 {
		// Distinct from "absent": a zero-length ring is a truncated write, not a fresh
		// filesystem, and treating it as fresh would regenerate over existing data.
		return nil, exitcodes.NewErr(fmt.Sprintf("key ring file %q is empty", filename), exitcodes.LoadConf)
	}
	if err := json.Unmarshal(js, kr); err != nil {
		return nil, exitcodes.NewErr(fmt.Sprintf("failed to parse key ring %q: %v", filename, err), exitcodes.LoadConf)
	}
	if err := kr.Validate(); err != nil {
		return nil, err
	}
	return kr, nil
}

// Validate checks that every entry carries the material needed to recover its key.
func (kr *KeyRing) Validate() error {
	for i, e := range kr.Keys {
		if e.KeyID == "" {
			return fmt.Errorf("key ring entry %d has an empty KeyID", i)
		}
		if len(e.Ciphertext) == 0 {
			return fmt.Errorf("key ring entry %d has an empty Ciphertext", i)
		}
	}
	return nil
}

// Active returns the newest entry, which is the one new content is encrypted under. Reads will
// need to reach the older entries once Phase-3 rotation retains them; until then the ring holds a
// single key and this is the whole of its read API.
func (kr *KeyRing) Active() (KeyRingEntry, error) {
	if len(kr.Keys) == 0 {
		return KeyRingEntry{}, fmt.Errorf("key ring is empty (no data key has been generated yet)")
	}
	return kr.Keys[len(kr.Keys)-1], nil
}

// WriteFile atomically replaces the key-ring file. The first mount encrypts data under this key
// immediately afterwards, so a partial or lost write would leave that data unrecoverable.
func (kr *KeyRing) WriteFile() error {
	if err := kr.Validate(); err != nil {
		return err
	}
	return writeJSONAtomic(kr.filename, kr)
}

// WriteFileUnderLock is WriteFile for a caller holding the filesystem's exclusive lock (see
// generateInitialDataKey). It first clears a tmp file left behind by a crashed earlier attempt,
// which would otherwise fail the exclusive create forever. That is only safe because the lock
// means nobody else can be mid-write — do not call it without one.
func (kr *KeyRing) WriteFileUnderLock() error {
	os.Remove(kr.filename + ".tmp")
	return kr.WriteFile()
}
