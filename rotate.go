package main

import (
	"errors"
	"fmt"
	"log"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/internal/tkc"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// rotateTrigger says why a rotation was asked for.
type rotateTrigger struct {
	// manual is a ctlsock rotation, which always adds a key.
	manual bool
	// pastIdx is, for any other trigger, the index the rotation is meant to move past: the op counter's
	// head, or the index the heartbeat reported. A head already beyond it means another mount rotated.
	pastIdx uint16
}

// Learning a key a sibling published backs off per index after a failure, so a bad or bogus index
// costs one unwrap per interval.
const (
	learnBackoffMin = time.Second
	learnBackoffMax = time.Minute
)

// keyRotator is this mount's view of the key ring. It learns the entries other mounts publish,
// rotates by publishing or adopting the next entry, and counts the encrypt operations drawn under
// each key.
type keyRotator struct {
	// rotateLock makes rotations in this process sequential.
	rotateLock sync.Mutex
	// ringLock guards ring, held and the learning state, and orders installs. It is held across an
	// unwrap but never across a generate.
	ringLock sync.Mutex
	// lock guards the op accounting and writeCreatedAt, and is never held across I/O.
	lock sync.Mutex
	// flushMu makes flushes sequential, and close waits for one in progress.
	flushMu sync.Mutex

	mountID       string
	readOnly      bool
	backend       cryptocore.AEADTypeEnum
	ivBits        int
	cEnc          *contentenc.ContentEnc
	nameTransform *nametransform.NameTransform

	ring *configfile.KeyRing
	// held is how many ring indices have keys installed, holes included.
	held    int
	holes   []uint16
	retryAt map[uint16]time.Time
	backoff map[uint16]time.Duration
	// refused carries the key service's refusal of an unwrap to the monitor, which ends the mount over it.
	refused chan error
	// headStuckSince is when the ring's head first could not be learned, zero while it is held.
	headStuckSince time.Time
	closed         bool

	// counters holds every op counter contentenc handed out, per index; the draws on a counter keep
	// counting after the write key moves on. base is what was absorbed from dead mounts' shards.
	counters       map[uint16][]*atomic.Uint64
	base           map[uint16]uint64
	written        map[uint16]uint64
	writeCreatedAt time.Time
}

// newKeyRotator returns the rotator for a mount whose key sets hold every entry of kr.
func newKeyRotator(mountID string, kr *configfile.KeyRing, holes []uint16, readOnly bool, backend cryptocore.AEADTypeEnum,
	ivBits int, cEnc *contentenc.ContentEnc, nameTransform *nametransform.NameTransform) (*keyRotator, error) {
	active, err := kr.Active()
	if err != nil {
		return nil, err
	}
	r := &keyRotator{mountID: mountID, readOnly: readOnly, backend: backend, ivBits: ivBits, cEnc: cEnc,
		nameTransform: nameTransform, ring: kr, held: len(kr.Keys), holes: holes,
		retryAt: map[uint16]time.Time{}, backoff: map[uint16]time.Duration{}, refused: make(chan error, 1),
		counters: map[uint16][]*atomic.Uint64{}, base: map[uint16]uint64{}, written: map[uint16]uint64{},
		writeCreatedAt: active.CreatedAt}
	idx, ctr := cEnc.OpCounter()
	r.counters[idx] = append(r.counters[idx], ctr)
	cEnc.SetKeyLearner(r.learnOnMiss)
	nameTransform.SetKeyLearner(r.learnOnMiss)
	return r, nil
}

// writeKey returns the ring index this mount writes under and the key service's stamp on its key.
func (r *keyRotator) writeKey() (uint16, time.Time) {
	r.lock.Lock()
	defer r.lock.Unlock()
	return r.cEnc.WriteKeyIdx(), r.writeCreatedAt
}

// keyHoles returns the indices this mount holds no key for: missing entries and keys that would not
// unwrap, including a sibling's that are not learned yet.
func (r *keyRotator) keyHoles() []uint16 {
	r.ringLock.Lock()
	defer r.ringLock.Unlock()
	holes := append([]uint16(nil), r.holes...)
	for idx := r.held; idx < len(r.ring.Keys); idx++ {
		holes = append(holes, uint16(idx))
	}
	return holes
}

// refresh learns every entry other mounts have published since the last refresh.
func (r *keyRotator) refresh() error {
	r.ringLock.Lock()
	defer r.ringLock.Unlock()
	return r.refreshLocked()
}

// learnOnMiss is asked by contentenc and nametransform for an index this mount does not hold. It makes
// one attempt, within the index's backoff, and reports whether the index is now held.
func (r *keyRotator) learnOnMiss(keyIdx uint16) bool {
	r.ringLock.Lock()
	defer r.ringLock.Unlock()
	if r.closed {
		return false
	}
	if int(keyIdx) < r.held {
		return true
	}
	if time.Now().Before(r.retryAt[uint16(r.held)]) {
		return false
	}
	if err := r.refreshLocked(); err != nil {
		tlog.Info.Printf("Learning key-ring index %d: %v", keyIdx, err)
		return false
	}
	return int(keyIdx) < r.held
}

func (r *keyRotator) refreshLocked() error {
	if r.closed {
		return nil
	}
	if _, err := r.ring.Refresh(); err != nil {
		return err
	}
	lastGood := -1
	for r.held < len(r.ring.Keys) {
		idx := uint16(r.held)
		e := r.ring.Keys[idx]
		if e.Missing() {
			r.installLocked(idx, nil)
			continue
		}
		if time.Now().Before(r.retryAt[idx]) {
			break
		}
		key, err := tkc.DataKey().UnwrapTKFSDataKey(e.KeyID, e.Ciphertext)
		if err != nil {
			if errors.Is(err, tkc.ErrDenied) || errors.Is(err, tkc.ErrSharedStorageRefused) {
				select {
				case r.refused <- err:
				default:
				}
			}
			d := min(max(2*r.backoff[idx], learnBackoffMin), learnBackoffMax)
			r.backoff[idx], r.retryAt[idx] = d, time.Now().Add(d)
			tlog.Info.Printf("Key-ring index %d, published by another mount, could not be unwrapped (%v); retrying in %v",
				idx, err, d)
			break
		}
		delete(r.backoff, idx)
		delete(r.retryAt, idx)
		r.installLocked(idx, key)
		lastGood = int(idx)
	}
	if r.held < len(r.ring.Keys) {
		if r.headStuckSince.IsZero() {
			r.headStuckSince = time.Now()
		}
	} else {
		r.headStuckSince = time.Time{}
	}
	if lastGood >= 0 && uint16(lastGood) > r.cEnc.WriteKeyIdx() {
		r.setWriteLocked(uint16(lastGood))
		tlog.Info.Printf("Writing under key-ring index %d, published by another mount", lastGood)
	}
	return nil
}

// installLocked installs the key at idx, or a hole for a nil key, and zeroes the key.
func (r *keyRotator) installLocked(idx uint16, key []byte) {
	if key == nil {
		if err := r.cEnc.InstallKey(idx, nil); err != nil {
			log.Panicf("rotate: %v", err)
		}
		if err := r.nameTransform.InstallCipher(idx, nil); err != nil {
			log.Panicf("rotate: %v", err)
		}
		r.holes = append(r.holes, idx)
	} else {
		core := cryptocore.New(key, r.backend, r.ivBits)
		clear(key)
		if err := r.cEnc.InstallKey(idx, core.AEADCipher); err != nil {
			log.Panicf("rotate: %v", err)
		}
		if err := r.nameTransform.InstallCipher(idx, core.EMECipher); err != nil {
			log.Panicf("rotate: %v", err)
		}
	}
	r.held++
}

func (r *keyRotator) setWriteLocked(idx uint16) {
	ctr, err := r.cEnc.SetWriteKey(idx)
	if err != nil {
		log.Panicf("rotate: %v", err)
	}
	if err := r.nameTransform.SetWriteCipher(idx); err != nil {
		log.Panicf("rotate: %v", err)
	}
	r.lock.Lock()
	r.counters[idx] = append(r.counters[idx], ctr)
	r.writeCreatedAt = r.ring.Keys[idx].CreatedAt
	r.lock.Unlock()
}

// headStuck reports whether the ring's head has been unlearnable for longer than d.
func (r *keyRotator) headStuck(d time.Duration) bool {
	r.ringLock.Lock()
	defer r.ringLock.Unlock()
	return !r.headStuckSince.IsZero() && time.Since(r.headStuckSince) > d
}

// rotate makes a fresh data key the write key, or adopts the one another mount published for the same
// trigger. Nothing on disk is re-encrypted.
func (r *keyRotator) rotate(t rotateTrigger) (uint16, error) {
	r.rotateLock.Lock()
	defer r.rotateLock.Unlock()
	if r.readOnly {
		return 0, errors.New("a read-only mount cannot rotate")
	}
	r.ringLock.Lock()
	if r.closed {
		r.ringLock.Unlock()
		return 0, errClosed
	}
	err := r.refreshLocked()
	head, held, kekID := len(r.ring.Keys)-1, r.held, r.ring.KekID()
	r.ringLock.Unlock()
	if err != nil {
		return 0, err
	}
	// Another mount already rotated past it. Until its entry is learned this mount writes under the
	// old key, which the stuck-head watchdog bounds.
	if !t.manual && head > int(t.pastIdx) {
		return r.cEnc.WriteKeyIdx(), nil
	}
	if held <= head {
		return 0, fmt.Errorf("key-ring index %d, published by another mount, is not learned yet", held)
	}
	if head+1 > math.MaxUint16 {
		return 0, configfile.ErrKeyRingFull
	}
	dk, err := tkc.DataKey().GenerateTKFSDataKey()
	if err != nil {
		return 0, fmt.Errorf("failed to generate a data key: %w", err)
	}
	defer clear(dk.Plaintext)
	// One KEK serves an instance for life, so a generate that answers with a different one means
	// the key service minted a second master — the state that would make the ring name two.
	if dk.KeyID != kekID {
		return 0, fmt.Errorf("the key service wrapped the new data key under KEK %q, but this filesystem's ring names %q",
			dk.KeyID, kekID)
	}

	r.ringLock.Lock()
	defer r.ringLock.Unlock()
	if r.closed {
		return 0, errClosed
	}
	if err := r.refreshLocked(); err != nil {
		return 0, err
	}
	next := len(r.ring.Keys)
	if !t.manual && next-1 > head {
		tlog.Info.Printf("Another mount rotated to key-ring index %d first; adopting it", next-1)
		return r.cEnc.WriteKeyIdx(), nil
	}
	if r.held < next {
		return 0, fmt.Errorf("key-ring index %d, published by another mount, is not learned yet", r.held)
	}
	if next > math.MaxUint16 {
		return 0, configfile.ErrKeyRingFull
	}
	won, err := r.ring.Publish(uint16(next), configfile.KeyRingEntry{
		KeyID:      dk.KeyID,
		Ciphertext: dk.Ciphertext,
		CreatedAt:  dk.CreatedAt,
	}, r.mountID)
	if err != nil {
		return 0, fmt.Errorf("failed to persist the new key-ring entry: %w", err)
	}
	if !won {
		if err := r.refreshLocked(); err != nil {
			return 0, err
		}
		if t.manual && r.held < len(r.ring.Keys) {
			return 0, fmt.Errorf("another mount published key-ring index %d first, and its key is not learned yet", next)
		}
		tlog.Info.Printf("Another mount published key-ring index %d first; adopting it", next)
		return r.cEnc.WriteKeyIdx(), nil
	}
	r.installLocked(uint16(next), dk.Plaintext)
	r.setWriteLocked(uint16(next))
	tlog.Info.Printf("Rotated to key-ring index %d", next)
	return uint16(next), nil
}

// opTotal is this mount's count of encrypt operations under idx. Caller holds lock.
func (r *keyRotator) opTotal(idx uint16) uint64 {
	total := r.base[idx]
	for _, c := range r.counters[idx] {
		total += c.Load()
	}
	return total
}

// flushOpCounts writes this mount's op counts into its shards and reports whether the head's count,
// summed over every mount, has reached threshold, along with the head it judged. The caller rotates,
// since rotate() takes the same locks.
func (r *keyRotator) flushOpCounts(threshold uint64) (rotateDue bool, head uint16, err error) {
	if r.readOnly {
		return false, 0, nil
	}
	r.flushMu.Lock()
	defer r.flushMu.Unlock()
	if err := r.refresh(); err != nil {
		return false, 0, err
	}
	r.ringLock.Lock()
	if r.closed {
		r.ringLock.Unlock()
		return false, 0, nil
	}
	// The write key, which is the head unless a newer entry could not be learned yet.
	head, ring := r.cEnc.WriteKeyIdx(), r.ring
	r.ringLock.Unlock()

	if err := r.writeShards(ring, head); err != nil {
		return false, head, err
	}
	shards, err := ring.OpShards()
	if err != nil {
		return false, head, err
	}
	var mine time.Time
	for _, s := range shards {
		if s.Idx == head && s.MountID == r.mountID {
			mine = s.ModTime
		}
	}
	var sum uint64
	var dead []configfile.OpShard
	for _, s := range shards {
		switch {
		case s.Idx < head:
			// Its key is no longer the write key anywhere, so its budget no longer matters.
			if err := ring.RemoveOpShard(s); err != nil {
				tlog.Info.Printf("Removing a stale op-count shard: %v", err)
			}
		case s.Idx > head || s.MountID == r.mountID:
		case s.Bad:
			// Unknown count: rotating retires the index, and the shard with it.
			rotateDue = true
		case !mine.IsZero() && mine.Sub(s.ModTime) > 3*heartbeatInterval:
			dead = append(dead, s)
		default:
			sum += s.Count
		}
	}
	r.lock.Lock()
	for _, s := range dead {
		r.base[head] += s.Count
	}
	sum += r.opTotal(head)
	r.lock.Unlock()
	if len(dead) > 0 {
		// Ours carries their count before theirs goes, so a crash can only count it twice.
		if err := r.writeShards(ring, head); err != nil {
			return false, head, err
		}
		for _, s := range dead {
			if err := ring.RemoveOpShard(s); err != nil {
				tlog.Info.Printf("Removing a dead mount's op-count shard: %v", err)
			}
		}
	}
	ring.RemoveStaleStaging(time.Hour)
	return rotateDue || sum >= threshold, head, nil
}

// writeShards writes this mount's shard for every index from head on whose count moved. The head's is
// always rewritten: its mtime is how other mounts see this one is alive.
func (r *keyRotator) writeShards(ring *configfile.KeyRing, head uint16) error {
	r.lock.Lock()
	totals := map[uint16]uint64{}
	for idx := range r.counters {
		if t := r.opTotal(idx); idx == head || (idx > head && t != r.written[idx]) {
			totals[idx] = t
		}
	}
	r.lock.Unlock()
	for idx, t := range totals {
		if err := ring.WriteOpShard(idx, r.mountID, t); err != nil {
			return fmt.Errorf("failed to persist the key-ring op counter: %w", err)
		}
		r.lock.Lock()
		r.written[idx] = t
		r.lock.Unlock()
	}
	return nil
}

// errClosed is a rotation asked of a mount that has already made its final flush.
var errClosed = errors.New("the mount is shutting down")

// close stops learning, rotating and flushing, so nothing writes the cipherdir after the final flush.
func (r *keyRotator) close() {
	r.flushMu.Lock()
	defer r.flushMu.Unlock()
	r.ringLock.Lock()
	r.closed = true
	r.ringLock.Unlock()
}
