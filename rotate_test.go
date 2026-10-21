package main

import (
	"bytes"
	"crypto/cipher"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"sync"
	"testing"
	"time"

	"github.com/rfjakob/eme"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/internal/tkc"
)

// entry builds a ring entry whose wrapped key is ct.
func entry(ct string) configfile.KeyRingEntry {
	return configfile.KeyRingEntry{KeyID: "kek-instance", Ciphertext: []byte(ct)}
}

// Auto-rotation is not something a deployment opts out of. The one exception is -ro, which
// performs no encrypt operations and may not write the cipherdir at all.
func TestAutoRotateThreshold(t *testing.T) {
	cases := []struct {
		name string
		args argContainer
		want uint64
	}{
		{"default", argContainer{}, defaultRotateOpThreshold},
		{"explicit", argContainer{rotateOpThreshold: 4096}, 4096},
		{"-sharedstorage does not turn it off", argContainer{sharedstorage: true}, defaultRotateOpThreshold},
		{"-ro turns it off", argContainer{ro: true}, 0},
		{"-ro overrides an explicit threshold", argContainer{rotateOpThreshold: 4096, ro: true}, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := autoRotateThreshold(&c.args); got != c.want {
				t.Errorf("autoRotateThreshold = %d, want %d", got, c.want)
			}
		})
	}
}

// A new ring entry carries the key service's stamp, not this host's clock, and becomes the key the
// heartbeat reports.
func TestRotateStoresTheKeyServicesStamp(t *testing.T) {
	r, dir := newTestRotator(t, "")
	_, previous := r.writeKey()
	start := time.Now()
	idx, err := r.rotate(rotateTrigger{manual: true})
	if err != nil {
		t.Fatal(err)
	}
	// The mock key service stamps from a fixed past epoch, so a stamp from this host's clock is
	// never older than start.
	got := loadRing(t, dir).Keys[idx].CreatedAt
	if !got.Before(start) || !got.After(previous) {
		t.Errorf("rotated entry CreatedAt = %v, want the key service's stamp, newer than %v", got, previous)
	}
	if gotIdx, gotAt := r.writeKey(); gotIdx != idx || !gotAt.Equal(got) {
		t.Errorf("write key = (%d, %v), want (%d, %v)", gotIdx, gotAt, idx, got)
	}
}

// A mount writes under, and reports, the ring's newest entry.
func TestNewKeyRotatorWritesUnderTheNewestEntry(t *testing.T) {
	dir := t.TempDir()
	if err := configfile.CreateKeyRingDir(dir); err != nil {
		t.Fatal(err)
	}
	kr := loadRing(t, dir)
	var aeads []cipher.AEAD
	var emes []*eme.EMECipher
	var core *cryptocore.CryptoCore
	for n := range 3 {
		e := entry("dek")
		e.CreatedAt = time.Date(2001, 1, 1, n, 0, 0, 0, time.UTC)
		if _, err := kr.Publish(uint16(n), e, "test"); err != nil {
			t.Fatal(err)
		}
		core = cryptocore.New(make([]byte, cryptocore.KeyLen), cryptocore.BackendGoGCM, contentenc.DefaultIVBits)
		aeads = append(aeads, core.AEADCipher)
		emes = append(emes, core.EMECipher)
	}
	newRotator := func(kr *configfile.KeyRing) (*keyRotator, error) {
		return newKeyRotator("m", kr, nil, false, cryptocore.BackendGoGCM, contentenc.DefaultIVBits,
			contentenc.New(core, aeads, contentenc.DefaultBS), nametransform.New(emes, false, 0, false, nil, false))
	}
	r, err := newRotator(loadRing(t, dir))
	if err != nil {
		t.Fatal(err)
	}
	if idx, at := r.writeKey(); idx != 2 || !at.Equal(kr.Keys[2].CreatedAt) {
		t.Errorf("write key = (%d, %v), want (2, %v)", idx, at, kr.Keys[2].CreatedAt)
	}
	if _, err := newRotator(loadRing(t, t.TempDir())); err == nil {
		t.Error("an empty ring has no key to write under")
	}
}

// So does the first mount's entry, along with the root diriv.
func TestGenerateInitialDataKeyStoresTheKeyServicesStamp(t *testing.T) {
	connectTestKMS(t)
	dir := t.TempDir()
	if err := configfile.CreateKeyRingDir(dir); err != nil {
		t.Fatal(err)
	}
	kr := loadRing(t, dir)
	start := time.Now()
	if key := generateInitialDataKey(&argContainer{cipherdir: dir, _mountID: "first"}, kr, false, false); key == nil {
		t.Fatal("an uncontested first mount must use its own key")
	}
	kr = loadRing(t, dir)
	if got := kr.Keys[0].CreatedAt; got.IsZero() || !got.Before(start) {
		t.Errorf("first entry CreatedAt = %v, want the key service's stamp", got)
	}
	assertRootDirIV(t, dir)
}

// publishPeerFirstMount publishes entry 0 and the root diriv as a racing first mount would.
func publishPeerFirstMount(t *testing.T, dir string) configfile.KeyRingEntry {
	t.Helper()
	dk, err := tkc.DataKey().GenerateTKFSDataKey()
	if err != nil {
		t.Fatal(err)
	}
	e := configfile.KeyRingEntry{KeyID: dk.KeyID, Ciphertext: dk.Ciphertext, CreatedAt: dk.CreatedAt}
	if won, err := loadRing(t, dir).Publish(0, e, "peer"); err != nil || !won {
		t.Fatalf("peer publish: won=%v, %v", won, err)
	}
	if err := publishRootDirIV(&argContainer{cipherdir: dir, _mountID: "peer"}, false); err != nil {
		t.Fatal(err)
	}
	return e
}

func assertRootDirIV(t *testing.T, dir string) []byte {
	t.Helper()
	record, err := os.ReadFile(filepath.Join(dir, nametransform.DirIVFilename))
	if err != nil {
		t.Fatal(err)
	}
	if _, idx, err := nametransform.CheckDirIVRecord(record, false); err != nil || idx != 0 {
		t.Errorf("root diriv: index %d, %v", idx, err)
	}
	return record
}

// A first mount that loses entry 0 to a racing one discards its key, takes the winner's, and keeps
// the winner's root diriv.
func TestGenerateInitialDataKeyLosesTheRace(t *testing.T) {
	connectTestKMS(t)
	for _, payload := range []bool{false, true} {
		t.Run(fmt.Sprintf("peer payload %v", payload), func(t *testing.T) {
			dir := t.TempDir()
			if err := configfile.CreateKeyRingDir(dir); err != nil {
				t.Fatal(err)
			}
			kr := loadRing(t, dir)
			won := publishPeerFirstMount(t, dir)
			diriv := assertRootDirIV(t, dir)
			if payload {
				// A winner serves only after publishing entry 0, so its files imply the entry.
				if err := os.WriteFile(filepath.Join(dir, "payload"), nil, 0600); err != nil {
					t.Fatal(err)
				}
			}
			if key := generateInitialDataKey(&argContainer{cipherdir: dir, _mountID: "loser"}, kr, false, false); key != nil {
				t.Error("the loser returned its own key")
			}
			if len(kr.Keys) != 1 || !bytes.Equal(kr.Keys[0].Ciphertext, won.Ciphertext) {
				t.Errorf("loser's ring = %+v, want the winner's entry", kr.Keys)
			}
			if got := assertRootDirIV(t, dir); !bytes.Equal(got, diriv) {
				t.Error("the loser replaced the winner's root diriv")
			}
		})
	}
}

// fakeConnector fails the first failures calls with err, then succeeds.
type fakeConnector struct {
	err      error
	failures int
	calls    int
}

func (f *fakeConnector) GenerateTKFSDataKey() (tkc.TKFSDataKey, error) { return tkc.TKFSDataKey{}, nil }
func (f *fakeConnector) AdoptIdentity(string) error                    { return nil }
func (f *fakeConnector) Close() error                                  { return nil }

func (f *fakeConnector) UnwrapTKFSDataKey(keyID string, ct []byte) ([]byte, error) {
	f.calls++
	if f.calls <= f.failures {
		return nil, f.err
	}
	return []byte("plaintext"), nil
}

// A 403 is the key service's decision and is not retried; anything else is an outage and is, since a
// blip would otherwise leave a hole until the next remount.
func TestUnwrapDataKeyRetriesOutagesButNotRefusals(t *testing.T) {
	defer func(d time.Duration) { unwrapRetryDelay = d }(unwrapRetryDelay)
	unwrapRetryDelay = time.Microsecond

	cases := []struct {
		name      string
		err       error
		failures  int
		wantCalls int
		wantErr   bool
	}{
		{"succeeds first time", nil, 0, 1, false},
		{"a blip is retried and recovers", errors.New("connection refused"), 1, 2, false},
		{"recovers on the last attempt", errors.New("i/o timeout"), unwrapAttempts - 1, unwrapAttempts, false},
		{"gives up after the budget", errors.New("connection refused"), unwrapAttempts + 5, unwrapAttempts, true},
		{"a refusal is not retried", fmt.Errorf("gateway: %w", tkc.ErrDenied), 99, 1, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			f := &fakeConnector{err: c.err, failures: c.failures}
			_, err := unwrapDataKey(f, 1, entry("dek-1"))
			if got := err != nil; got != c.wantErr {
				t.Errorf("error = %v, want error %v", err, c.wantErr)
			}
			if f.calls != c.wantCalls {
				t.Errorf("calls = %d, want %d", f.calls, c.wantCalls)
			}
		})
	}
}

// A refusal of any key-service call is a revocation, or SharedStorageRefused for -sharedstorage, so it
// exits as a refused heartbeat would; anything else exits the caller's code.
func TestKeyServiceExit(t *testing.T) {
	for _, c := range []struct {
		err        error
		code, want int
	}{
		{fmt.Errorf("gateway unwrap: %w", tkc.ErrSharedStorageRefused), exitcodes.Other, exitcodes.SharedStorageRefused},
		{fmt.Errorf("gateway unwrap: %w", tkc.ErrDenied), exitcodes.Other, exitcodes.Revoked},
		{fmt.Errorf("gateway generate: %w", tkc.ErrDenied), exitcodes.RotateFailed, exitcodes.Revoked},
		{fmt.Errorf("gateway generate: %w", tkc.ErrSharedStorageRefused), exitcodes.RotateFailed, exitcodes.SharedStorageRefused},
		{errors.New("connection refused"), exitcodes.Other, exitcodes.Other},
		{errors.New("connection refused"), exitcodes.RotateFailed, exitcodes.RotateFailed},
	} {
		if got := keyServiceExit(c.err, c.code); got != c.want {
			t.Errorf("keyServiceExit(%v, %d) = %d, want %d", c.err, c.code, got, c.want)
		}
	}
}

// A read-only mount neither rotates nor writes a shard.
func TestReadOnlyRotatorWritesNothing(t *testing.T) {
	_, dir := newTestRotator(t, "")
	r := newTestMount(t, loadRing(t, dir), nil, true)
	if _, err := r.rotate(rotateTrigger{manual: true}); err == nil {
		t.Error("a read-only rotator rotated")
	}
	encrypt(r, 3)
	if due, _, err := r.flushOpCounts(1); due || err != nil {
		t.Errorf("flushOpCounts = (%v, %v), want nothing due", due, err)
	}
	if s := opShards(t, dir); len(s) != 0 {
		t.Errorf("a read-only rotator wrote shards %+v", s)
	}
}

// encrypt draws n nonces under the write key.
func encrypt(r *keyRotator, n int) {
	for range n {
		r.cEnc.EncryptBlock([]byte("x"), 0, nil, r.cEnc.WriteKeyIdx())
	}
}

// opShards lists the cipherdir's op-count shards.
func opShards(t *testing.T, dir string) []configfile.OpShard {
	t.Helper()
	s, err := loadRing(t, dir).OpShards()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// shardCount is mountID's shard under idx, or -1 if it has none.
func shardCount(t *testing.T, dir string, idx uint16, mountID string) int64 {
	t.Helper()
	for _, s := range opShards(t, dir) {
		if s.Idx == idx && s.MountID == mountID {
			return int64(s.Count)
		}
	}
	return -1
}

// shardPath is where mountID's shard under idx lives.
func shardPath(dir string, idx uint16, mountID string) string {
	return filepath.Join(configfile.KeyRingDir(dir), "ops", fmt.Sprintf("%05d.%s", idx, mountID))
}

// Crossing the threshold rotates; the outgoing index keeps what it spent until a flush under the new
// head removes it, and the new one is credited only with its own ops.
func TestFlushOpCountsRotatesAtThreshold(t *testing.T) {
	r, dir := newTestRotator(t, "")
	m, _, code := newTestMonitor(t, r, nil)
	m.opThreshold = 4

	encrypt(r, 3)
	m.flushOpCounts()
	if got := shardCount(t, dir, 0, r.mountID); got != 3 {
		t.Fatalf("under the threshold: shard 0 = %d, want 3", got)
	}
	encrypt(r, 1)
	m.flushOpCounts()
	if n := len(loadRing(t, dir).Keys); n != 2 {
		t.Fatalf("at the threshold: ring has %d entries, want 2", n)
	}
	if got := shardCount(t, dir, 0, r.mountID); got != 4 {
		t.Errorf("at the threshold: shard 0 = %d, want 4", got)
	}
	if got := r.cEnc.WriteKeyIdx(); got != 1 {
		t.Errorf("write index = %d, want 1", got)
	}
	encrypt(r, 2)
	m.flushOpCounts()
	if got := shardCount(t, dir, 1, r.mountID); got != 2 {
		t.Errorf("after the rotation: shard 1 = %d, want 2", got)
	}
	if got := shardCount(t, dir, 0, r.mountID); got != -1 {
		t.Errorf("shard 0 = %d after a flush under head 1, want it removed", got)
	}
	if *code != -1 {
		t.Errorf("exit code = %d, want none", *code)
	}
}

// A count earlier mounts left at the threshold rotates on the first flush, before any new op, whether
// that mount is still alive or long gone.
func TestFlushOpCountsRotatesAnInheritedCount(t *testing.T) {
	for _, dead := range []bool{false, true} {
		t.Run(fmt.Sprintf("dead %v", dead), func(t *testing.T) {
			r, dir := newTestRotator(t, "")
			if err := loadRing(t, dir).WriteOpShard(0, "earlier", 10); err != nil {
				t.Fatal(err)
			}
			if dead {
				old := time.Now().Add(-4 * heartbeatInterval)
				if err := os.Chtimes(shardPath(dir, 0, "earlier"), old, old); err != nil {
					t.Fatal(err)
				}
			}
			m, _, code := newTestMonitor(t, r, nil)
			m.opThreshold = 10
			m.flushOpCounts()
			if n := len(loadRing(t, dir).Keys); n != 2 {
				t.Errorf("ring has %d entries, want 2", n)
			}
			if *code != -1 {
				t.Errorf("exit code = %d, want none", *code)
			}
		})
	}
}

// An unparsable shard has an unknown count, so its index is due; rotating retires it.
func TestFlushOpCountsBadShardIsDue(t *testing.T) {
	r, dir := newTestRotator(t, "")
	if err := os.WriteFile(shardPath(dir, 0, "garbled"), []byte("{"), 0600); err != nil {
		t.Fatal(err)
	}
	due, head, err := r.flushOpCounts(defaultRotateOpThreshold)
	if err != nil || !due || head != 0 {
		t.Fatalf("flushOpCounts = (%v, %d, %v), want due at head 0", due, head, err)
	}
	if _, err := r.rotate(rotateTrigger{pastIdx: head}); err != nil {
		t.Fatal(err)
	}
	if due, _, err := r.flushOpCounts(defaultRotateOpThreshold); err != nil || due {
		t.Errorf("flushOpCounts after the rotation = (%v, %v), want not due", due, err)
	}
	if got := shardCount(t, dir, 0, "garbled"); got != -1 {
		t.Error("the bad shard survived its index's retirement")
	}
}

// testFileID is the file ID the cross-mount checks encrypt under.
var testFileID = bytes.Repeat([]byte{7}, 16)

// assertCrossRead checks that what w encrypts under idx, content and names, r decrypts: both hold the
// key that is on disk at idx.
func assertCrossRead(t *testing.T, w, r *keyRotator, idx uint16) {
	t.Helper()
	ct := slices.Clone(w.cEnc.EncryptBlock([]byte("payload"), 3, testFileID, idx))
	if pt, err := r.cEnc.DecryptBlock(ct, 3, testFileID, idx); err != nil || string(pt) != "payload" {
		t.Errorf("index %d: content written by one mount reads back as (%q, %v) in the other", idx, pt, err)
	}
	iv := bytes.Repeat([]byte{1}, nametransform.DirIVLen)
	cname, err := w.nameTransform.EncryptName("file", iv, idx)
	if err != nil {
		t.Fatalf("index %d: %v", idx, err)
	}
	if name, err := r.nameTransform.DecryptName(cname, iv, idx); err != nil || name != "file" {
		t.Errorf("index %d: a name encrypted by one mount decrypts as (%q, %v) in the other", idx, name, err)
	}
}

// assertConverged checks that both mounts hold every entry on disk, write under its head, and agree
// on every key.
func assertConverged(t *testing.T, dir string, rs ...*keyRotator) {
	t.Helper()
	kr := loadRing(t, dir)
	head := uint16(len(kr.Keys) - 1)
	for i, e := range kr.Keys {
		if e.Missing() {
			t.Errorf("entry %d is missing", i)
		}
	}
	for _, r := range rs {
		if err := r.refresh(); err != nil {
			t.Fatal(err)
		}
		if got := r.cEnc.WriteKeyIdx(); got != head {
			t.Errorf("content write index = %d, want the head %d", got, head)
		}
		if got := r.nameTransform.WriteKeyIdx(); got != head {
			t.Errorf("name write index = %d, want the head %d", got, head)
		}
	}
	for idx := range head + 1 {
		assertCrossRead(t, rs[0], rs[1], idx)
		assertCrossRead(t, rs[1], rs[0], idx)
	}
}

// Two mounts rotating at once, by ctlsock and by count or rekey, never lose an entry: every index on
// disk is one a rotation returned, and both mounts hold the key on disk there.
func TestRotateConcurrentlyOnTwoMounts(t *testing.T) {
	a, dir := newTestRotator(t, "")
	b := mountTestRotator(t, dir)
	const n = 6
	returned := make([][]uint16, 2)
	errs := make(chan error, 2*n)
	var wg sync.WaitGroup
	for i, r := range []*keyRotator{a, b} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for k := range n {
				trigger := rotateTrigger{manual: k%2 == i, pastIdx: r.cEnc.WriteKeyIdx()}
				idx, err := r.rotate(trigger)
				if err != nil {
					errs <- err
					return
				}
				returned[i] = append(returned[i], idx)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
	head := len(loadRing(t, dir).Keys) - 1
	if head < n || head > 2*n {
		t.Errorf("ring head = %d after %d rotations on each of two mounts, want %d to %d", head, n, n, 2*n)
	}
	var all []uint16
	for i, got := range returned {
		if !slices.IsSorted(got) || len(slices.Compact(slices.Clone(got))) != len(got) {
			t.Errorf("mount %d's rotations returned %v, want strictly increasing indices", i, got)
		}
		all = append(all, got...)
	}
	slices.Sort(all)
	all = slices.Compact(all)
	if len(all) != head || (head > 0 && (all[0] != 1 || int(all[len(all)-1]) != head)) {
		t.Errorf("rotations returned %v, want every index 1..%d", all, head)
	}
	assertConverged(t, dir, a, b)
}

// Rotations both mounts make for the same reason add one entry between them, however many race.
func TestRotateForOneTriggerOnTwoMountsAddsOneEntry(t *testing.T) {
	a, dir := newTestRotator(t, "")
	b := mountTestRotator(t, dir)
	for round := range uint16(3) {
		var wg sync.WaitGroup
		got := make([]uint16, 4)
		errs := make([]error, 4)
		for i, r := range []*keyRotator{a, b, a, b} {
			wg.Add(1)
			go func() {
				defer wg.Done()
				got[i], errs[i] = r.rotate(rotateTrigger{pastIdx: round})
			}()
		}
		wg.Wait()
		for i := range got {
			if errs[i] != nil || got[i] != round+1 {
				t.Errorf("round %d, rotation %d = (%d, %v), want %d", round, i, got[i], errs[i], round+1)
			}
		}
		if n := len(loadRing(t, dir).Keys); n != int(round)+2 {
			t.Fatalf("round %d: ring has %d entries, want %d", round, n, round+2)
		}
		for _, r := range []*keyRotator{a, b} {
			if w := r.cEnc.WriteKeyIdx(); w != round+1 {
				t.Errorf("round %d: write index = %d, want %d", round, w, round+1)
			}
		}
	}
	assertConverged(t, dir, a, b)
}

// A mount that has not seen a sibling's rotation adopts or builds on it, and learns a sibling's
// entries by refresh and by meeting their index.
func TestRotatorLaggingASibling(t *testing.T) {
	a, dir := newTestRotator(t, "")
	b := mountTestRotator(t, dir)
	rotate := func(r *keyRotator, trig rotateTrigger, want uint16) {
		t.Helper()
		if got, err := r.rotate(trig); err != nil || got != want {
			t.Fatalf("rotate(%+v) = (%d, %v), want %d", trig, got, err, want)
		}
	}

	rotate(a, rotateTrigger{manual: true}, 1)
	if got := b.cEnc.WriteKeyIdx(); got != 0 {
		t.Fatalf("b's write index = %d before it refreshed, want 0", got)
	}
	// b rotating for its own stale head adopts a's entry.
	rotate(b, rotateTrigger{pastIdx: 0}, 1)
	if n := len(loadRing(t, dir).Keys); n != 2 {
		t.Errorf("ring has %d entries after an adopting rotation, want 2", n)
	}
	// A lagging ctlsock rotation builds on top.
	rotate(a, rotateTrigger{manual: true}, 2)
	rotate(b, rotateTrigger{manual: true}, 3)

	if err := a.refresh(); err != nil {
		t.Fatal(err)
	}
	if got := a.cEnc.WriteKeyIdx(); got != 3 {
		t.Errorf("a's write index = %d after refresh, want 3", got)
	}

	// Content under an index a does not hold yet.
	rotate(b, rotateTrigger{manual: true}, 4)
	assertCrossRead(t, b, a, 4)
	if got := a.cEnc.WriteKeyIdx(); got != 4 {
		t.Errorf("a's write index = %d after a miss on 4, want 4", got)
	}
	// Writing into a sibling's newer file, as doWrite does.
	rotate(b, rotateTrigger{manual: true}, 5)
	if err := a.cEnc.EnsureKey(5); err != nil {
		t.Fatal(err)
	}
	assertCrossRead(t, a, b, 5)
	// A name under an index a does not hold yet.
	rotate(b, rotateTrigger{manual: true}, 6)
	iv := bytes.Repeat([]byte{2}, nametransform.DirIVLen)
	cname, err := b.nameTransform.EncryptName("dir", iv, 6)
	if err != nil {
		t.Fatal(err)
	}
	if name, err := a.nameTransform.DecryptName(cname, iv, 6); err != nil || name != "dir" {
		t.Errorf("a decrypts b's name under 6 as (%q, %v)", name, err)
	}
	if err := a.cEnc.EnsureKey(100); !errors.Is(err, contentenc.ErrKeyMissing) {
		t.Errorf("EnsureKey past the head = %v, want ErrKeyMissing", err)
	}
	assertConverged(t, dir, a, b)
}

// An index deleted from disk below the head becomes a hole, and the mount writes under the head.
func TestRotatorRefreshLoadsAGapAsAHole(t *testing.T) {
	a, dir := newTestRotator(t, "")
	b := mountTestRotator(t, dir)
	for range 2 {
		if _, err := a.rotate(rotateTrigger{manual: true}); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Remove(filepath.Join(configfile.KeyRingDir(dir), "00001")); err != nil {
		t.Fatal(err)
	}
	if err := b.refresh(); err != nil {
		t.Fatal(err)
	}
	if got := b.keyHoles(); !slices.Equal(got, []uint16{1}) {
		t.Errorf("holes = %v, want [1]", got)
	}
	if got := b.cEnc.WriteKeyIdx(); got != 2 {
		t.Errorf("write index = %d, want 2", got)
	}
	if err := b.cEnc.EnsureKey(1); !errors.Is(err, contentenc.ErrKeyMissing) {
		t.Errorf("EnsureKey(1) = %v, want ErrKeyMissing", err)
	}
	assertCrossRead(t, a, b, 2)
}

// publishUnwrappable publishes, as a sibling would, an entry the key service cannot unwrap.
func publishUnwrappable(t *testing.T, dir string) uint16 {
	t.Helper()
	kr := loadRing(t, dir)
	idx := uint16(len(kr.Keys))
	e := configfile.KeyRingEntry{KeyID: kr.KekID(), Ciphertext: []byte("not a wrapped key"), CreatedAt: time.Now()}
	if won, err := kr.Publish(idx, e, "sibling"); err != nil || !won {
		t.Fatalf("publish: won=%v, %v", won, err)
	}
	return idx
}

// An entry that does not unwrap leaves the mount writing under the key it has, is not asked for
// again within its backoff, and marks the head stuck.
func TestRotatorUnlearnableEntryBacksOff(t *testing.T) {
	r, dir := newTestRotator(t, "")
	idx := publishUnwrappable(t, dir)
	if err := r.refresh(); err != nil {
		t.Fatal(err)
	}
	if got := r.cEnc.WriteKeyIdx(); got != 0 {
		t.Errorf("write index = %d, want 0", got)
	}
	if got := r.backoff[idx]; got != learnBackoffMin {
		t.Errorf("backoff = %v, want %v", got, learnBackoffMin)
	}
	if r.learnOnMiss(idx) {
		t.Error("learnOnMiss reported an unwrappable index as held")
	}
	if err := r.cEnc.EnsureKey(idx); !errors.Is(err, contentenc.ErrKeyMissing) {
		t.Errorf("EnsureKey = %v, want ErrKeyMissing", err)
	}
	if got := r.backoff[idx]; got != learnBackoffMin {
		t.Errorf("backoff = %v after misses within it, want %v: a miss inside the backoff must not unwrap", got, learnBackoffMin)
	}
	if !r.headStuck(0) || r.headStuck(time.Hour) {
		t.Error("headStuck should report the unlearned head as stuck since the refresh")
	}
	select {
	case err := <-r.refused:
		t.Errorf("refused %v; a bad ciphertext is not a refusal", err)
	default:
	}
}

// The Phase-3 failures that made it single-mount.
func TestRotatorPhase3Regressions(t *testing.T) {
	t.Run("both rotations persist", func(t *testing.T) {
		a, dir := newTestRotator(t, "")
		b := mountTestRotator(t, dir)
		ia, err := a.rotate(rotateTrigger{manual: true})
		if err != nil {
			t.Fatal(err)
		}
		ib, err := b.rotate(rotateTrigger{manual: true})
		if err != nil {
			t.Fatal(err)
		}
		if ia != 1 || ib != 2 {
			t.Errorf("rotations returned %d and %d, want 1 and 2", ia, ib)
		}
		assertConverged(t, dir, a, b)
	})

	t.Run("a lagging mount writes into a sibling's newer file", func(t *testing.T) {
		a, dir := newTestRotator(t, "")
		b := mountTestRotator(t, dir)
		idx, err := a.rotate(rotateTrigger{manual: true})
		if err != nil {
			t.Fatal(err)
		}
		if err := b.cEnc.EnsureKey(idx); err != nil {
			t.Fatal(err)
		}
		b.cEnc.EncryptBlock([]byte("x"), 0, testFileID, idx)
	})

	t.Run("a flush credits the index the draws were made under", func(t *testing.T) {
		a, dir := newTestRotator(t, "")
		b := mountTestRotator(t, dir)
		mb, _, code := newTestMonitor(t, b, nil)
		mb.opThreshold = 5
		encrypt(b, 4)
		if _, err := a.rotate(rotateTrigger{manual: true}); err != nil {
			t.Fatal(err)
		}
		encrypt(b, 1)
		mb.flushOpCounts()
		if n := len(loadRing(t, dir).Keys); n != 2 {
			t.Errorf("ring has %d entries; index 0's draws were charged to index 1", n)
		}
		if got := shardCount(t, dir, 1, b.mountID); got != 0 {
			t.Errorf("b's shard 1 = %d, want 0", got)
		}
		if *code != -1 {
			t.Errorf("exit code = %d, want none", *code)
		}
	})
}

// A flush sums the head's shards over every mount, and a flush that rotates leaves the sibling to
// start the new head at zero.
func TestFlushOpCountsSumsMounts(t *testing.T) {
	a, dir := newTestRotator(t, "")
	b := mountTestRotator(t, dir)
	ma, _, codeA := newTestMonitor(t, a, nil)
	mb, _, codeB := newTestMonitor(t, b, nil)
	ma.opThreshold, mb.opThreshold = 10, 10

	encrypt(a, 3)
	ma.flushOpCounts()
	encrypt(b, 4)
	mb.flushOpCounts()
	if n := len(loadRing(t, dir).Keys); n != 1 {
		t.Fatalf("ring has %d entries at a sum of 7, want 1", n)
	}
	encrypt(a, 3)
	ma.flushOpCounts()
	if n := len(loadRing(t, dir).Keys); n != 2 {
		t.Fatalf("ring has %d entries at a sum of 10, want 2", n)
	}
	mb.flushOpCounts()
	if n := len(loadRing(t, dir).Keys); n != 2 {
		t.Errorf("ring has %d entries; b rotated again on the retired index's count", n)
	}
	if got := b.cEnc.WriteKeyIdx(); got != 1 {
		t.Errorf("b's write index = %d, want 1", got)
	}
	var left []string
	for _, s := range opShards(t, dir) {
		left = append(left, fmt.Sprintf("%d:%d", s.Idx, s.Count))
	}
	if !slices.Equal(left, []string{"1:0"}) {
		t.Errorf("shards = %v, want only b's at the new head: [1:0]", left)
	}
	if *codeA != -1 || *codeB != -1 {
		t.Errorf("exit codes %d, %d; want none", *codeA, *codeB)
	}
}

// A shard whose mount stopped flushing long ago is absorbed into a live mount's, counted once.
func TestFlushOpCountsAbsorbsADeadMount(t *testing.T) {
	a, dir := newTestRotator(t, "")
	b := mountTestRotator(t, dir)
	encrypt(b, 5)
	if _, _, err := b.flushOpCounts(defaultRotateOpThreshold); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-3*heartbeatInterval - time.Minute)
	if err := os.Chtimes(shardPath(dir, 0, b.mountID), old, old); err != nil {
		t.Fatal(err)
	}
	encrypt(a, 2)
	due, _, err := a.flushOpCounts(7)
	if err != nil || !due {
		t.Errorf("flushOpCounts = (%v, %v), want due at 2+5", due, err)
	}
	if got := shardCount(t, dir, 0, b.mountID); got != -1 {
		t.Errorf("the dead mount's shard is still there, count %d", got)
	}
	if got := shardCount(t, dir, 0, a.mountID); got != 7 {
		t.Errorf("a's shard = %d, want 7", got)
	}
	encrypt(a, 1)
	if due, _, err := a.flushOpCounts(9); err != nil || due {
		t.Errorf("flushOpCounts at 8 = (%v, %v), want not due: the dead count is counted once", due, err)
	}
	if got := shardCount(t, dir, 0, a.mountID); got != 8 {
		t.Errorf("a's shard = %d, want 8", got)
	}
}

// Draws that land on a counter after the write key moved stay with their index, and never reach the
// new head's shard.
func TestFlushOpCountsKeepsLateDrawsWithTheirIndex(t *testing.T) {
	r, dir := newTestRotator(t, "")
	_, old := r.cEnc.OpCounter()
	encrypt(r, 3)
	if _, err := r.rotate(rotateTrigger{manual: true}); err != nil {
		t.Fatal(err)
	}
	old.Add(4)
	if got := r.opTotal(0); got != 7 {
		t.Errorf("index 0's total = %d, want 7", got)
	}
	encrypt(r, 2)
	if _, _, err := r.flushOpCounts(defaultRotateOpThreshold); err != nil {
		t.Fatal(err)
	}
	if got := shardCount(t, dir, 1, r.mountID); got != 2 {
		t.Errorf("shard 1 = %d, want 2", got)
	}
}

// A sibling that rotated away from a spent key, with an entry this mount cannot unwrap yet, does not end
// this mount at once: the trigger is satisfied, and the head watchdog allows a heartbeat interval.
func TestFlushOpCountsWaitsOutAnUnlearnedSiblingRotation(t *testing.T) {
	r, dir := newTestRotator(t, "")
	if err := loadRing(t, dir).WriteOpShard(0, "sibling", 10); err != nil {
		t.Fatal(err)
	}
	publishUnwrappable(t, dir)
	m, _, code := newTestMonitor(t, r, nil)
	m.opThreshold = 10
	m.flushOpCounts()
	if *code != -1 {
		t.Errorf("exit code = %d, want none until the head has been stuck for %v", *code, heartbeatInterval)
	}
	if n := len(loadRing(t, dir).Keys); n != 2 {
		t.Errorf("ring has %d entries, want 2: the sibling's rotation satisfies the trigger", n)
	}
}

// After the final flush a rotation, from ctlsock or a sibling's trigger, publishes nothing.
func TestRotateAfterCloseIsRefused(t *testing.T) {
	r, dir := newTestRotator(t, "")
	r.close()
	if _, err := r.rotate(rotateTrigger{manual: true}); !errors.Is(err, errClosed) {
		t.Fatalf("rotate after close: %v, want errClosed", err)
	}
	if n := len(loadRing(t, dir).Keys); n != 1 {
		t.Errorf("ring has %d entries after a refused rotation, want 1", n)
	}
}
