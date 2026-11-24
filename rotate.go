package main

import (
	"bytes"
	"errors"
	"fmt"
	"log"
	"slices"
	"sync"
	"time"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/internal/tkc"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// keyRotator appends a new data key to the ring and switches new writes to it. Every rotation
// trigger goes through the same rotate() — the ctlsock command, a rekey the heartbeat brings back,
// and the op counter.
type keyRotator struct {
	// lock makes a rotation atomic against another one in this process. The ring append, the
	// content key and the name key have to move together: new files are stamped with an index
	// that both halves must already hold.
	lock          sync.Mutex
	configPath    string
	backend       cryptocore.AEADTypeEnum
	ivBits        int
	cEnc          *contentenc.ContentEnc
	nameTransform *nametransform.NameTransform
	// flushed is the write key's op count already credited to the ring. Guarded by lock.
	flushed uint64
	// writeCreatedAt is the key service's stamp on the write key. Guarded by lock.
	writeCreatedAt time.Time
	// entries is the ring this mount holds keys for. Guarded by lock.
	entries []configfile.KeyRingEntry
	// generate asks the key service for a new data key; nil means tkc.DataKey(). Tests replace it.
	generate func() (tkc.TKFSDataKey, error)
	// gate, if set, refuses every rotation once the mount has halted.
	gate *keyGate
}

// newKeyRotator returns the rotator for a mount whose key ring is kr, writing under its newest entry.
func newKeyRotator(configPath string, kr *configfile.KeyRing, backend cryptocore.AEADTypeEnum, ivBits int,
	cEnc *contentenc.ContentEnc, nameTransform *nametransform.NameTransform) (*keyRotator, error) {
	active, err := kr.Active()
	if err != nil {
		return nil, err
	}
	return &keyRotator{configPath: configPath, backend: backend, ivBits: ivBits, cEnc: cEnc,
		nameTransform: nameTransform, writeCreatedAt: active.CreatedAt, entries: slices.Clone(kr.All())}, nil
}

// writeKey returns the ring index this mount writes under and the key service's stamp on its key.
func (r *keyRotator) writeKey() (uint16, time.Time) {
	r.lock.Lock()
	defer r.lock.Unlock()
	return r.cEnc.WriteKeyIdx(), r.writeCreatedAt
}

// errRotationFatal marks a rotation failure once a new data key is in hand: a KEK other than this
// filesystem's means the key service holds a second master for it, and a key ring that will not take or
// persist the new entry is a cipherdir the mount cannot write. It suspends file operations at once,
// where a failure to get the key at all is struck heartbeatFailureLimit times first.
var errRotationFatal = errors.New("rotation failed after the key service answered")

// errHalted refuses a rotation on a halted mount.
var errHalted = errors.New("the mount has halted; only a remount rotates it")

// rotate appends a freshly generated data key to the ring and makes it the key new content, names
// and directories are written under. Nothing on disk is re-encrypted.
func (r *keyRotator) rotate() (uint16, error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	if r.gate != nil && r.gate.halted.Load() {
		return 0, errHalted
	}

	keyRing, err := r.loadRing()
	if err != nil {
		return 0, err
	}
	active, err := keyRing.Active()
	if err != nil {
		return 0, err
	}
	generate := r.generate
	if generate == nil {
		generate = tkc.DataKey().GenerateTKFSDataKey
	}
	dk, err := generate()
	if err != nil {
		return 0, fmt.Errorf("failed to generate a data key: %w", err)
	}
	defer clear(dk.Plaintext)
	// generate is a gateway round trip, the widest window for another host's write.
	if keyRing, err = r.loadRing(); err != nil {
		return 0, err
	}
	// One KEK serves an instance for life, so a generate that answers with a different one means
	// the key service minted a second master — the state that would make the ring name two.
	if dk.KeyID != active.KeyID {
		return 0, fmt.Errorf("%w: the key service wrapped the new data key under KEK %q, but this filesystem's ring names %q",
			errRotationFatal, dk.KeyID, active.KeyID)
	}
	// Credit the outgoing key before it stops being the write key: AddKey starts a fresh counter,
	// and the ring only ever accumulates against the active entry.
	if outgoing := r.cEnc.OpCount(); outgoing > r.flushed {
		keyRing.AddOpCount(outgoing - r.flushed)
	}
	e := configfile.KeyRingEntry{
		KeyID:      dk.KeyID,
		Ciphertext: dk.Ciphertext,
		CreatedAt:  dk.CreatedAt,
	}
	idx, err := keyRing.Append(e)
	if err != nil {
		return 0, fmt.Errorf("%w: %w", errRotationFatal, err)
	}
	// Persist before use: anything encrypted under a key that is not recoverable from disk is
	// lost at unmount.
	if err := keyRing.WriteFile(); err != nil {
		return 0, fmt.Errorf("%w: failed to persist the new key-ring entry: %w", errRotationFatal, err)
	}
	r.entries = append(r.entries, e)
	core := cryptocore.New(dk.Plaintext, r.backend, r.ivBits)
	if got := r.cEnc.AddKey(core.AEADCipher); got != idx {
		log.Panicf("rotate: content key landed at index %d, the ring assigned %d", got, idx)
	}
	if got := r.nameTransform.AddCipher(core.EMECipher); got != idx {
		log.Panicf("rotate: name key landed at index %d, the ring assigned %d", got, idx)
	}
	// AddKey published a fresh zeroed counter, so nothing is outstanding against it.
	r.flushed = 0
	r.writeCreatedAt = dk.CreatedAt
	tlog.Info.Printf("Rotated to key-ring index %d", idx)
	return idx, nil
}

// flushOpCounts credits the encrypt operations since the last flush to the active entry's persisted
// count, which spans every mount, and reports whether that count has reached "threshold". The caller
// does the rotating, since rotate() takes the same lock.
func (r *keyRotator) flushOpCounts(threshold uint64) (rotateDue bool, err error) {
	r.lock.Lock()
	defer r.lock.Unlock()
	keyRing, err := r.loadRing()
	if err != nil {
		return false, err
	}
	// Wipe() publishes a fresh counter, which an unmount flush can race; the comparison keeps
	// that from wrapping.
	if count := r.cEnc.OpCount(); count > r.flushed {
		if keyRing.AddOpCount(count - r.flushed) {
			if err := keyRing.WriteFile(); err != nil {
				return false, fmt.Errorf("failed to persist the key-ring op counter: %w", err)
			}
		}
		r.flushed = count
	}
	active, err := keyRing.Active()
	if err != nil {
		return false, err
	}
	return active.OpCount >= threshold, nil
}

// errRingChanged marks a key ring on disk other than the one this mount holds keys for, which another
// host sharing the cipherdir wrote. Only a remount loads that host's entries.
var errRingChanged = errors.New("another host changed the key ring on disk; remount to load its entries")

// loadRing loads the ring on disk, refusing one that is not the ring this mount holds keys for, so a
// rotation or op count never lands on another host's entry. Call with lock held.
func (r *keyRotator) loadRing() (*configfile.KeyRing, error) {
	kr, err := configfile.LoadKeyRing(r.configPath)
	if err != nil {
		return nil, err
	}
	if !sameEntries(kr.All(), r.entries) {
		return nil, fmt.Errorf("%w (%d entries on disk, %d held)", errRingChanged, len(kr.All()), len(r.entries))
	}
	return kr, nil
}

// sameEntries reports whether two rings hold the same wrapped keys in the same order.
func sameEntries(a, b []configfile.KeyRingEntry) bool {
	return slices.EqualFunc(a, b, func(x, y configfile.KeyRingEntry) bool {
		return x.KeyID == y.KeyID && bytes.Equal(x.Ciphertext, y.Ciphertext)
	})
}
