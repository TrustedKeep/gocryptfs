package main

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
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
	r := newTestRotator(t, "")
	_, previous := r.writeKey()
	start := time.Now()
	idx, err := r.rotate()
	if err != nil {
		t.Fatal(err)
	}
	// The mock key service stamps from a fixed past epoch, so a stamp from this host's clock is
	// never older than start.
	got := loadRing(t, r).Keys[idx].CreatedAt
	if !got.Before(start) || !got.After(previous) {
		t.Errorf("rotated entry CreatedAt = %v, want the key service's stamp, newer than %v", got, previous)
	}
	if gotIdx, gotAt := r.writeKey(); gotIdx != idx || !gotAt.Equal(got) {
		t.Errorf("write key = (%d, %v), want (%d, %v)", gotIdx, gotAt, idx, got)
	}
}

// A mount writes under, and reports, the ring's newest entry.
func TestNewKeyRotatorWritesUnderTheNewestEntry(t *testing.T) {
	kr := &configfile.KeyRing{}
	var aeads []cipher.AEAD
	var core *cryptocore.CryptoCore
	for n := range 3 {
		e := entry("dek")
		e.CreatedAt = time.Date(2001, 1, 1, n, 0, 0, 0, time.UTC)
		kr.Append(e)
		core = cryptocore.New(make([]byte, cryptocore.KeyLen), cryptocore.BackendGoGCM, contentenc.DefaultIVBits)
		aeads = append(aeads, core.AEADCipher)
	}
	cEnc := contentenc.New(core, aeads, contentenc.DefaultBS)
	r, err := newKeyRotator("", kr, cryptocore.BackendGoGCM, contentenc.DefaultIVBits, cEnc, nil)
	if err != nil {
		t.Fatal(err)
	}
	if idx, at := r.writeKey(); idx != 2 || !at.Equal(kr.Keys[2].CreatedAt) {
		t.Errorf("write key = (%d, %v), want (2, %v)", idx, at, kr.Keys[2].CreatedAt)
	}
	if _, err := newKeyRotator("", &configfile.KeyRing{}, cryptocore.BackendGoGCM, contentenc.DefaultIVBits, cEnc, nil); err == nil {
		t.Error("an empty ring has no key to write under")
	}
}

// So does the first mount's entry.
func TestGenerateInitialDataKeyStoresTheKeyServicesStamp(t *testing.T) {
	connectOnce.Do(func() { tkc.Connect("", "", testNodeID, true, false, false) })
	dir := t.TempDir()
	kr, err := configfile.LoadKeyRing(filepath.Join(dir, configfile.ConfDefaultName))
	if err != nil {
		t.Fatal(err)
	}
	start := time.Now()
	generateInitialDataKey(&argContainer{cipherdir: dir}, kr, false, false)
	kr, err = configfile.LoadKeyRing(filepath.Join(dir, configfile.ConfDefaultName))
	if err != nil {
		t.Fatal(err)
	}
	if got := kr.Keys[0].CreatedAt; got.IsZero() || !got.Before(start) {
		t.Errorf("first entry CreatedAt = %v, want the key service's stamp", got)
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

// opCounts is each ring entry's persisted OpCount.
func opCounts(t *testing.T, r *keyRotator) (c []uint64) {
	for _, e := range loadRing(t, r).Keys {
		c = append(c, e.OpCount)
	}
	return c
}

// encrypt draws n nonces under the write key.
func encrypt(r *keyRotator, n int) {
	for range n {
		r.cEnc.EncryptBlock([]byte("x"), 0, nil, r.cEnc.WriteKeyIdx())
	}
}

// Crossing the threshold rotates; the outgoing entry keeps what it spent and the new one is credited
// only with its own ops.
func TestFlushOpCountsRotatesAtThreshold(t *testing.T) {
	r := newTestRotator(t, "")
	m, _, code := newTestMonitor(t, r, nil)
	m.opThreshold = 4

	encrypt(r, 3)
	m.flushOpCounts()
	if got := opCounts(t, r); !slices.Equal(got, []uint64{3}) {
		t.Fatalf("under the threshold: op counts %v, want [3]", got)
	}
	encrypt(r, 1)
	m.flushOpCounts()
	if got := opCounts(t, r); !slices.Equal(got, []uint64{4, 0}) {
		t.Fatalf("at the threshold: op counts %v, want [4 0]", got)
	}
	if got := r.cEnc.WriteKeyIdx(); got != 1 {
		t.Errorf("write index = %d, want 1", got)
	}
	encrypt(r, 2)
	m.flushOpCounts()
	if got := opCounts(t, r); !slices.Equal(got, []uint64{4, 2}) {
		t.Errorf("after the rotation: op counts %v, want [4 2]", got)
	}

	// A ring write renames a new file into place, so an unchanged inode means no write.
	ringPath := filepath.Join(filepath.Dir(r.configPath), configfile.KeyRingFileName)
	before, err := os.Stat(ringPath)
	if err != nil {
		t.Fatal(err)
	}
	m.flushOpCounts()
	after, err := os.Stat(ringPath)
	if err != nil {
		t.Fatal(err)
	}
	if !os.SameFile(before, after) {
		t.Error("a flush with nothing to credit rewrote the ring")
	}
	if *code != -1 {
		t.Errorf("exit code = %d, want none", *code)
	}
}

// A count earlier mounts left at the threshold rotates on the first flush, before any new op.
func TestFlushOpCountsRotatesAnInheritedCount(t *testing.T) {
	r := newTestRotator(t, "")
	kr := loadRing(t, r)
	kr.Keys[0].OpCount = 10
	if err := kr.WriteFile(); err != nil {
		t.Fatal(err)
	}
	m, _, code := newTestMonitor(t, r, nil)
	m.opThreshold = 10
	m.flushOpCounts()
	if n := len(loadRing(t, r).Keys); n != 2 {
		t.Errorf("ring has %d entries, want 2", n)
	}
	if *code != -1 {
		t.Errorf("exit code = %d, want none", *code)
	}
}
