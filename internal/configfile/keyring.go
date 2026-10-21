package configfile

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// KeyRingFileName is the key ring's directory in the cipherdir root. Each entry is a file of its own,
// written once and never changed, so mounts sharing the cipherdir never rewrite each other's state.
const KeyRingFileName = "KR"

const (
	keyRingOpsDir     = "ops"
	keyRingNodesDir   = "nodes"
	keyRingFormatName = "format"
	keyRingXattrLock  = "xattr.lock"
	keyRingTmpPrefix  = ".tmp."
)

// keyRingEntryName matches an entry's file name, its ring index in five decimal digits.
var keyRingEntryName = regexp.MustCompile(`^[0-9]{5}$`)

// KeyRingEntry is one gateway-wrapped master key. Its ring index, stamped into everything encrypted
// under it, is its file name.
type KeyRingEntry struct {
	// KeyID is the gateway KEK the Ciphertext is wrapped under, the same on every entry. It is also
	// the filesystem's KekID, so editing it names a different KEK or none.
	KeyID string
	// Ciphertext is the gateway-wrapped master key.
	Ciphertext []byte
	// CreatedAt is the key service's time for this key, which the heartbeat reports for the active entry.
	CreatedAt time.Time
}

// Missing reports an index below the head with no entry on disk.
func (e KeyRingEntry) Missing() bool {
	return e.KeyID == ""
}

// KeyRing is the on-disk key ring, ciphertext only. The newest entry is the active write key.
type KeyRing struct {
	// Keys is indexed by ring index. An index whose entry is gone from disk holds a zero entry.
	Keys []KeyRingEntry
	dir  string
}

// KeyRingDir is where the key ring of the filesystem at cipherdir lives.
func KeyRingDir(cipherdir string) string {
	return filepath.Join(cipherdir, KeyRingFileName)
}

// XattrLockPath is the file -sharedstorage mounts lock while stamping an inode's xattr key-index marker.
func XattrLockPath(cipherdir string) string {
	return filepath.Join(KeyRingDir(cipherdir), keyRingXattrLock)
}

// CreateKeyRingDir creates the ring's directories if they do not exist yet, durably.
func CreateKeyRingDir(cipherdir string) error {
	dir := KeyRingDir(cipherdir)
	if err := os.Mkdir(dir, 0700); err != nil && !os.IsExist(err) {
		return err
	}
	if fi, err := os.Lstat(dir); err != nil {
		return err
	} else if !fi.IsDir() {
		return errOldRingFile(dir)
	}
	for _, d := range []string{dir, filepath.Join(dir, keyRingOpsDir), filepath.Join(dir, keyRingNodesDir)} {
		if err := os.Mkdir(d, 0700); err != nil && !os.IsExist(err) {
			return err
		}
	}
	if err := syncDir(dir); err != nil {
		return err
	}
	return syncDir(cipherdir)
}

// LoadKeyRing loads the key ring of the filesystem at cipherdir. A missing ring is a fresh filesystem
// and loads empty.
func LoadKeyRing(cipherdir string) (*KeyRing, error) {
	kr := &KeyRing{dir: KeyRingDir(cipherdir)}
	fi, err := os.Lstat(kr.dir)
	if os.IsNotExist(err) {
		return kr, nil
	}
	if err != nil {
		return nil, exitcodes.NewErr(err.Error(), exitcodes.OpenConf)
	}
	if !fi.IsDir() {
		return nil, errOldRingFile(kr.dir)
	}
	if _, err := kr.Refresh(); err != nil {
		return nil, err
	}
	return kr, nil
}

func errOldRingFile(path string) error {
	return exitcodes.NewErr(fmt.Sprintf("%s is a key ring file from an earlier version, which kept the ring in one "+
		"file; re-initialize the filesystem and copy the data across", path), exitcodes.LoadConf)
}

// Refresh reads the entries other mounts have published since the ring was loaded and returns how many
// indices it grew by. Entries are never rewritten, so only indices past the known ones are read.
func (kr *KeyRing) Refresh() (grew int, err error) {
	// A fresh open of the directory is what makes NFS revalidate it.
	names, err := readDirNames(kr.dir)
	if err != nil {
		return 0, exitcodes.NewErr(err.Error(), exitcodes.OpenConf)
	}
	known := len(kr.Keys)
	head := -1
	found := map[int]bool{}
	for _, name := range names {
		if !keyRingEntryName.MatchString(name) {
			continue
		}
		idx, _ := strconv.Atoi(name)
		if idx > math.MaxUint16 || idx < known {
			continue
		}
		found[idx] = true
		head = max(head, idx)
	}
	if head < known {
		return 0, nil
	}
	grown := make([]KeyRingEntry, head+1-known)
	for idx := known; idx <= head; idx++ {
		// A readdir can miss a name created while it ran, so a gap is looked up before it is a hole.
		if !found[idx] {
			if _, err := os.Lstat(kr.entryPath(uint16(idx))); err != nil {
				continue
			}
		}
		e, err := kr.readEntry(uint16(idx))
		if err != nil {
			return 0, err
		}
		grown[idx-known] = e
	}
	// Learned entries are written under next, so they must not vanish in a crash.
	if err := syncDir(kr.dir); err != nil {
		return 0, exitcodes.NewErr(err.Error(), exitcodes.OpenConf)
	}
	next := &KeyRing{Keys: append(slices.Clip(kr.Keys), grown...), dir: kr.dir}
	if err := next.Validate(); err != nil {
		// Off disk, a bad entry is a malformed file.
		return 0, exitcodes.NewErr(err.Error(), exitcodes.LoadConf)
	}
	kr.Keys = next.Keys
	return len(grown), nil
}

func (kr *KeyRing) entryPath(idx uint16) string {
	return filepath.Join(kr.dir, fmt.Sprintf("%05d", idx))
}

func (kr *KeyRing) readEntry(idx uint16) (KeyRingEntry, error) {
	path := kr.entryPath(idx)
	js, err := os.ReadFile(path)
	if err != nil {
		return KeyRingEntry{}, exitcodes.NewErr(err.Error(), exitcodes.OpenConf)
	}
	var e KeyRingEntry
	if err := json.Unmarshal(js, &e); err != nil {
		return KeyRingEntry{}, exitcodes.NewErr(fmt.Sprintf("failed to parse key ring entry %q: %v", path, err), exitcodes.LoadConf)
	}
	if e.Missing() {
		return KeyRingEntry{}, exitcodes.NewErr(fmt.Sprintf("key ring entry %q has an empty KeyID", path), exitcodes.LoadConf)
	}
	return e, nil
}

// Validate checks that every entry can be recovered and that the ring names one KEK. The caller
// attaches the exit code.
func (kr *KeyRing) Validate() error {
	if len(kr.Keys)-1 > math.MaxUint16 {
		return fmt.Errorf("key ring has %d entries, more than a uint16 index can name", len(kr.Keys))
	}
	if n := len(kr.Keys); n > 0 && kr.Keys[n-1].Missing() {
		return fmt.Errorf("key ring entry %d, the newest, is missing", n-1)
	}
	id := kr.KekID()
	for i, e := range kr.Keys {
		if e.Missing() {
			continue
		}
		if len(e.Ciphertext) == 0 {
			return fmt.Errorf("key ring entry %d has an empty Ciphertext", i)
		}
		if e.CreatedAt.IsZero() {
			return fmt.Errorf("key ring entry %d has no CreatedAt", i)
		}
		if e.KeyID != id {
			return fmt.Errorf("key ring entry %d is wrapped under KEK %q but the ring names %q; a ring names one KEK",
				i, e.KeyID, id)
		}
	}
	return nil
}

// KekID is the filesystem's identity: the KEK id its entries share, or "" before the first generate.
func (kr *KeyRing) KekID() string {
	for _, e := range kr.Keys {
		if !e.Missing() {
			return e.KeyID
		}
	}
	return ""
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

// All returns every entry, oldest first. Missing ones are zero entries.
func (kr *KeyRing) All() []KeyRingEntry {
	return kr.Keys
}

// ErrKeyRingFull means every index a uint16 can name already has an entry.
var ErrKeyRingFull = errors.New("the key ring is full: every uint16 index is taken")

// Publish creates the entry at idx and reports whether this call did. Losing means another mount
// published a different key there first; on success the entry is added to kr.
func (kr *KeyRing) Publish(idx uint16, e KeyRingEntry, mountID string) (won bool, err error) {
	if int(idx) != len(kr.Keys) {
		return false, fmt.Errorf("publishing key ring index %d, but the ring has %d entries", idx, len(kr.Keys))
	}
	next := &KeyRing{Keys: append(slices.Clip(kr.Keys), e), dir: kr.dir}
	if err := next.Validate(); err != nil {
		return false, err
	}
	js, err := json.MarshalIndent(e, "", "\t")
	if err != nil {
		return false, err
	}
	// 0400: these files should be kept secret and are never written in place.
	if won, err = PublishExclusive(kr.entryPath(idx), js, 0400, kr.dir, mountID); err != nil || !won {
		return won, err
	}
	kr.Keys = next.Keys
	return true, nil
}

var publishSeq atomic.Uint64

// stagingPath is a name in dir that no other process or call uses.
func stagingPath(dir, mountID string) string {
	return filepath.Join(dir, fmt.Sprintf("%s%s.%d", keyRingTmpPrefix, mountID, publishSeq.Add(1)))
}

// PublishExclusive creates dst with data unless it exists, staging in stagingDir, and reports whether
// dst now holds data. The link is the arbiter between mounts; an existing dst that is byte-identical is
// a link of ours that NFS reported as failed.
func PublishExclusive(dst string, data []byte, mode os.FileMode, stagingDir, mountID string) (won bool, err error) {
	tmp := stagingPath(stagingDir, mountID)
	fd, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return false, err
	}
	defer os.Remove(tmp)
	_, err = fd.Write(data)
	if err == nil {
		err = syncFile(fd)
	}
	if err2 := fd.Close(); err == nil {
		err = err2
	}
	if err != nil {
		return false, err
	}
	var linkErr error
	for attempt := 0; ; attempt++ {
		if linkErr = os.Link(tmp, dst); linkErr == nil {
			won = true
			break
		}
		// Without hard links there is no -sharedstorage (see backingfs), so a non-shared mount's lock
		// already makes this the only writer.
		if errors.Is(linkErr, syscall.EPERM) || errors.Is(linkErr, syscall.EOPNOTSUPP) {
			if _, err := os.Lstat(dst); os.IsNotExist(err) {
				if err := os.Rename(tmp, dst); err != nil {
					return false, err
				}
				won = true
				break
			}
		}
		got, err := os.ReadFile(dst)
		if err == nil {
			won = bytes.Equal(got, data)
			break
		}
		if !os.IsNotExist(err) {
			return false, err
		}
		if attempt == 2 {
			return false, linkErr
		}
	}
	// Before reporting either outcome: a mount adopting the winner's file must not write under it
	// until it is durable.
	if err := syncDir(filepath.Dir(dst)); err != nil {
		return false, err
	}
	return won, nil
}

// OpShard is one mount's count of encrypt operations under one ring index.
type OpShard struct {
	Idx     uint16
	MountID string
	Count   uint64
	ModTime time.Time
	// Bad means the shard could not be parsed, so Count is unknown.
	Bad  bool
	path string
}

// WriteOpShard records total as mountID's count under idx, replacing its previous one.
func (kr *KeyRing) WriteOpShard(idx uint16, mountID string, total uint64) error {
	js, err := json.Marshal(struct{ Count uint64 }{total})
	if err != nil {
		return err
	}
	tmp := stagingPath(kr.dir, mountID)
	fd, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return err
	}
	_, err = fd.Write(js)
	if err == nil {
		err = syncFile(fd)
	}
	if err2 := fd.Close(); err == nil {
		err = err2
	}
	if err == nil {
		err = os.Rename(tmp, filepath.Join(kr.dir, keyRingOpsDir, fmt.Sprintf("%05d.%s", idx, mountID)))
	}
	if err != nil {
		os.Remove(tmp)
	}
	return err
}

// OpShards lists every mount's op-count shards. A shard that vanishes while being read is skipped.
func (kr *KeyRing) OpShards() ([]OpShard, error) {
	dir := filepath.Join(kr.dir, keyRingOpsDir)
	names, err := readDirNames(dir)
	if err != nil {
		return nil, err
	}
	var shards []OpShard
	for _, name := range names {
		idxStr, mountID, ok := strings.Cut(name, ".")
		if !ok || !keyRingEntryName.MatchString(idxStr) || mountID == "" {
			continue
		}
		idx, _ := strconv.Atoi(idxStr)
		if idx > math.MaxUint16 {
			continue
		}
		s := OpShard{Idx: uint16(idx), MountID: mountID, path: filepath.Join(dir, name)}
		fi, err := os.Stat(s.path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		s.ModTime = fi.ModTime()
		js, err := os.ReadFile(s.path)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return nil, err
		}
		var v struct{ Count uint64 }
		if json.Unmarshal(js, &v) != nil {
			s.Bad = true
		}
		s.Count = v.Count
		shards = append(shards, s)
	}
	return shards, nil
}

// RemoveOpShard deletes a shard. One already gone is not an error.
func (kr *KeyRing) RemoveOpShard(s OpShard) error {
	if err := os.Remove(s.path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// RemoveStaleStaging deletes staging files older than age, which a killed mount left behind. Removing
// a live one fails its owner's publish.
func (kr *KeyRing) RemoveStaleStaging(age time.Duration) {
	names, err := readDirNames(kr.dir)
	if err != nil {
		return
	}
	cutoff := time.Now().Add(-age)
	for _, name := range names {
		if !strings.HasPrefix(name, keyRingTmpPrefix) {
			continue
		}
		path := filepath.Join(kr.dir, name)
		if fi, err := os.Lstat(path); err == nil && fi.ModTime().Before(cutoff) {
			os.Remove(path)
		}
	}
}

// formatRecord is what every mount sharing a ring must agree on, whatever config file it was given.
type formatRecord struct {
	Version      uint16
	FeatureFlags []string
	LongNameMax  uint8
}

// CheckFormat refuses a config that disagrees with the one the ring was first mounted with, recording
// cf as that one if no mount has yet. A read-only mount only compares.
func CheckFormat(cipherdir string, cf *ConfFile, mountID string, readOnly bool) error {
	rec := formatRecord{Version: cf.Version, FeatureFlags: slices.Sorted(slices.Values(cf.FeatureFlags)),
		LongNameMax: cf.LongNameMax}
	js, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	dir := KeyRingDir(cipherdir)
	path := filepath.Join(dir, keyRingFormatName)
	var same bool
	if readOnly {
		got, err := os.ReadFile(path)
		if os.IsNotExist(err) {
			return nil
		}
		if err != nil {
			return err
		}
		same = bytes.Equal(got, js)
	} else if same, err = PublishExclusive(path, js, 0400, dir, mountID); err != nil {
		return exitcodes.NewErr(fmt.Sprintf("cannot record the filesystem's format in %s: %v", path, err), exitcodes.WriteConf)
	}
	if !same {
		got, _ := os.ReadFile(path)
		return exitcodes.NewErr(fmt.Sprintf("this config file does not match the one the filesystem was first mounted "+
			"with (%s vs %s in %s); every mount of a cipherdir needs a config of the same format", js, got, path), exitcodes.LoadConf)
	}
	return nil
}

// ErrKeyRingInUse means another process holds the key-ring lock.
var ErrKeyRingInUse = errors.New("the key ring is in use by another process")

// LockKeyRing holds the cipherdir in shared or exclusive mode for as long as the returned file stays
// open, waiting up to "wait" for a holder that has unmounted but not yet exited. Shared mounts coexist;
// an exclusive one coexists with nothing.
func LockKeyRing(cipherdir string, shared bool, wait time.Duration) (*os.File, error) {
	f, err := os.Open(cipherdir)
	if err != nil {
		return nil, err
	}
	how := syscall.LOCK_EX
	if shared {
		how = syscall.LOCK_SH
	}
	if err := flockWait(f, how, wait); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrKeyRingInUse
		}
		return nil, err
	}
	return f, nil
}

// ErrNodeIDInUse means another mount of the cipherdir holds the NodeID.
var ErrNodeIDInUse = errors.New("another mount is using this NodeID")

// LockNodeID holds nodeID for as long as the returned file stays open, so two mounts cannot report as
// one. On NFS the lock is the server's, freed when a crashed holder's lease runs out.
func LockNodeID(cipherdir, nodeID string, wait time.Duration) (*os.File, error) {
	// Hashed, so a NodeID of any length or content makes a valid file name.
	sum := sha256.Sum256([]byte(nodeID))
	path := filepath.Join(KeyRingDir(cipherdir), keyRingNodesDir, hex.EncodeToString(sum[:]))
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		return nil, err
	}
	if err := flockWait(f, syscall.LOCK_EX, wait); err != nil {
		f.Close()
		if errors.Is(err, syscall.EWOULDBLOCK) {
			return nil, ErrNodeIDInUse
		}
		return nil, err
	}
	return f, nil
}

// flockWait takes the lock, waiting up to "wait" for a holder that has unmounted but not yet exited.
func flockWait(f *os.File, how int, wait time.Duration) error {
	deadline := time.Now().Add(wait)
	for {
		err := syscall.Flock(int(f.Fd()), how|syscall.LOCK_NB)
		if !errors.Is(err, syscall.EWOULDBLOCK) || !time.Now().Before(deadline) {
			return err
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func readDirNames(dir string) ([]string, error) {
	d, err := os.Open(dir)
	if err != nil {
		return nil, err
	}
	defer d.Close()
	return d.Readdirnames(-1)
}

// syncFile fsyncs fd, falling back to a global sync where the filesystem does not support it.
func syncFile(fd *os.File) error {
	if err := fd.Sync(); err != nil {
		// This can happen on network drives: FRITZ.NAS mounted on MacOS returns
		// "operation not supported": https://github.com/rfjakob/gocryptfs/issues/390
		if !errors.Is(err, syscall.EINVAL) && !errors.Is(err, syscall.ENOTSUP) {
			return err
		}
		tlog.Info.Printf("fsync is not supported here (%v); syncing everything instead", err)
		syscall.Sync()
	}
	return nil
}

// syncDir makes the entries of dir durable. A filesystem that cannot fsync a directory gets a global
// sync instead; any other failure is returned, since a ring entry that may vanish cannot be used.
func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		if errors.Is(err, syscall.EINVAL) || errors.Is(err, syscall.ENOTSUP) {
			syscall.Sync()
			return nil
		}
		return err
	}
	return nil
}
