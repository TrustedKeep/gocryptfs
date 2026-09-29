package configfile

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"syscall"
	"time"

	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
)

// KeyRingFileName is the key ring's file, next to gocryptfs.conf.
const KeyRingFileName = "KR"

// KeyRingTmpFileName is the staging file renamed over the ring on every write. Anything that lists
// the ring's directory has to know it.
const KeyRingTmpFileName = KeyRingFileName + ".tmp"

// KeyRingEntry is one gateway-wrapped master key. Its ring index, stamped into everything encrypted
// under it, is its position in KeyRing.Keys.
type KeyRingEntry struct {
	// KeyID is the gateway KEK the Ciphertext is wrapped under, the same on every entry. It is also
	// the filesystem's InstanceID, so editing it names a different KEK or none.
	KeyID string
	// Ciphertext is the gateway-wrapped master key.
	Ciphertext []byte
	// CreatedAt is the key service's time for this key, which the heartbeat reports for the active entry.
	CreatedAt time.Time
	// OpCount is the persisted encrypt-op count that drives auto-rotation. Only the active entry's grows.
	OpCount uint64 `json:",omitempty"`
}

// KeyRing is the on-disk key ring, ciphertext only. The newest entry is the active write key.
type KeyRing struct {
	Keys     []KeyRingEntry
	filename string
}

// InstanceID is the filesystem's identity: the KEK id its entries share, or "" before the first generate.
func (kr *KeyRing) InstanceID() string {
	if len(kr.Keys) == 0 {
		return ""
	}
	return kr.Keys[len(kr.Keys)-1].KeyID
}

func keyRingPath(confPath string) string {
	return filepath.Join(filepath.Dir(confPath), KeyRingFileName)
}

// LoadKeyRing loads the key ring beside the config at "confPath". A missing ring is a fresh
// filesystem and loads empty.
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
		// A truncated write, not a fresh filesystem: treating it as fresh would generate over existing data.
		return nil, exitcodes.NewErr(fmt.Sprintf("key ring file %q is empty", filename), exitcodes.LoadConf)
	}
	if err := json.Unmarshal(js, kr); err != nil {
		return nil, exitcodes.NewErr(fmt.Sprintf("failed to parse key ring %q: %v", filename, err), exitcodes.LoadConf)
	}
	if err := kr.Validate(); err != nil {
		// Off disk, a bad entry is a malformed file.
		return nil, exitcodes.NewErr(err.Error(), exitcodes.LoadConf)
	}
	return kr, nil
}

// Validate checks that every entry can be recovered and that the ring names one KEK. The caller
// attaches the exit code.
func (kr *KeyRing) Validate() error {
	for i, e := range kr.Keys {
		if e.KeyID == "" {
			return fmt.Errorf("key ring entry %d has an empty KeyID", i)
		}
		if len(e.Ciphertext) == 0 {
			return fmt.Errorf("key ring entry %d has an empty Ciphertext", i)
		}
		if e.KeyID != kr.Keys[0].KeyID {
			return fmt.Errorf("key ring entry %d is wrapped under KEK %q but entry 0 is under %q; a ring names one KEK",
				i, e.KeyID, kr.Keys[0].KeyID)
		}
	}
	return nil
}

// Active returns the newest entry, the one new content is written under.
func (kr *KeyRing) Active() (KeyRingEntry, error) {
	idx, err := kr.ActiveIdx()
	if err != nil {
		return KeyRingEntry{}, err
	}
	return kr.Keys[idx], nil
}

// ActiveIdx returns the index new data is stamped with.
func (kr *KeyRing) ActiveIdx() (uint16, error) {
	if len(kr.Keys) == 0 {
		return 0, fmt.Errorf("key ring is empty (no data key has been generated yet)")
	}
	return uint16(len(kr.Keys) - 1), nil
}

// All returns every entry, oldest first.
func (kr *KeyRing) All() []KeyRingEntry {
	return kr.Keys
}

// Append adds e as the active entry and returns its ring index. Indices are positions stamped on
// disk, so entries are never removed or reordered.
func (kr *KeyRing) Append(e KeyRingEntry) uint16 {
	kr.Keys = append(kr.Keys, e)
	return uint16(len(kr.Keys) - 1)
}

// AddOpCount credits delta to the active entry and reports whether anything changed.
func (kr *KeyRing) AddOpCount(delta uint64) bool {
	if delta == 0 || len(kr.Keys) == 0 {
		return false
	}
	kr.Keys[len(kr.Keys)-1].OpCount += delta
	return true
}

// WriteFile atomically replaces the key-ring file. A tmp file left by a killed write is cleared
// first, or it would fail the exclusive create forever.
func (kr *KeyRing) WriteFile() error {
	if err := kr.Validate(); err != nil {
		return err
	}
	os.Remove(filepath.Join(filepath.Dir(kr.filename), KeyRingTmpFileName))
	return writeJSONAtomic(kr.filename, kr)
}

// ErrKeyRingInUse means another process holds the key-ring lock.
var ErrKeyRingInUse = errors.New("the key ring is in use by another process")

// LockKeyRing makes this process the key ring's only user for as long as the returned file stays open,
// waiting up to "wait" for a holder that has unmounted but not yet exited. The lock is on the ring's
// directory because the ring itself is replaced by rename.
func LockKeyRing(confPath string, wait time.Duration) (*os.File, error) {
	f, err := os.Open(filepath.Dir(keyRingPath(confPath)))
	if err != nil {
		return nil, err
	}
	deadline := time.Now().Add(wait)
	for {
		err = syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
		if !errors.Is(err, syscall.EWOULDBLOCK) || !time.Now().Before(deadline) {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if err == nil {
		return f, nil
	}
	f.Close()
	if errors.Is(err, syscall.EWOULDBLOCK) {
		return nil, ErrKeyRingInUse
	}
	return nil, err
}
