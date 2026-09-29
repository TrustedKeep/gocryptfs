package main

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
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

// §0.8 contains an unavailable key to the files that need it, which is right for a key the service
// has *decided* not to return. Applying it to a blip instead turns one slow round trip into a mount
// that silently serves a truncated view of its own filesystem until someone remounts it — and a mount
// makes one round trip per retained entry, so a long ring gets many chances to hit one.
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
