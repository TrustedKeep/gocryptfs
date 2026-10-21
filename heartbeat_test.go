package main

import (
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/TrustedKeep/tkutils/v2/model"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/internal/tkc"
)

// testNodeID names this process's mock key store.
var testNodeID = fmt.Sprintf("gocryptfs-main-test-%d", os.Getpid())

var (
	connectOnce sync.Once
	connectErr  error
)

func TestMain(m *testing.M) {
	r := m.Run()
	os.Remove(filepath.Join(os.TempDir(), "tkfs_mock_gateway_"+testNodeID+".db"))
	os.Exit(r)
}

// connectTestKMS connects the process's mock key service and gives it the identity of one minted KEK,
// which every test filesystem shares.
func connectTestKMS(t *testing.T) {
	t.Helper()
	connectOnce.Do(func() {
		tkc.Connect(tkc.ConnectOptions{NodeID: testNodeID, MockStoreID: testNodeID, MockKMS: true})
		dk, err := tkc.DataKey().GenerateTKFSDataKey()
		if err == nil {
			err = tkc.DataKey().AdoptIdentity(dk.KeyID)
		}
		connectErr = err
	})
	if connectErr != nil {
		t.Fatal(connectErr)
	}
}

// newTestRotator returns a rotator over a one-entry ring in a fresh cipherdir, and the cipherdir.
// A non-empty keyID overrides the entry's KEK, which makes every rotation fail.
func newTestRotator(t *testing.T, keyID string) (*keyRotator, string) {
	t.Helper()
	connectTestKMS(t)
	dk, err := tkc.DataKey().GenerateTKFSDataKey()
	if err != nil {
		t.Fatal(err)
	}
	if keyID == "" {
		keyID = dk.KeyID
	}
	dir := t.TempDir()
	if err := configfile.CreateKeyRingDir(dir); err != nil {
		t.Fatal(err)
	}
	kr := loadRing(t, dir)
	if won, err := kr.Publish(0, configfile.KeyRingEntry{KeyID: keyID, Ciphertext: dk.Ciphertext, CreatedAt: dk.CreatedAt},
		"test-init"); err != nil || !won {
		t.Fatalf("publishing entry 0: won=%v, %v", won, err)
	}
	return newTestMount(t, kr, dk.Plaintext, false), dir
}

// mountTestRotator is another mount of the filesystem at dir, with its own key sets, ring view and mount ID.
func mountTestRotator(t *testing.T, dir string) *keyRotator {
	t.Helper()
	return newTestMount(t, loadRing(t, dir), nil, false)
}

// newTestMount builds a mount's key sets and rotator over kr as initFuseFrontend does.
func newTestMount(t *testing.T, kr *configfile.KeyRing, freshKey []byte, readOnly bool) *keyRotator {
	t.Helper()
	ks := buildKeySets(kr, freshKey, cryptocore.BackendGoGCM, contentenc.DefaultIVBits, false)
	r, err := newKeyRotator(hex.EncodeToString(cryptocore.RandBytes(16)), kr, ks.holes, readOnly,
		cryptocore.BackendGoGCM, contentenc.DefaultIVBits, contentenc.New(ks.core, ks.aeads, contentenc.DefaultBS),
		nametransform.New(ks.emeCiphers, false, 0, false, nil, false))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// loadRing reads the ring of the cipherdir at dir back from disk.
func loadRing(t *testing.T, dir string) *configfile.KeyRing {
	t.Helper()
	kr, err := configfile.LoadKeyRing(dir)
	if err != nil {
		t.Fatal(err)
	}
	return kr
}

// fakeHeartbeater answers every beat with answer, or err, and records the index and stamp each beat
// reported.
type fakeHeartbeater struct {
	answer model.TKFSHeartbeatResponse
	err    error
	// laterErr, if set, answers every beat after the first.
	laterErr error
	// rekeyUntil, if set, answers a rekey while the reported index is below it, as keep holds a
	// directive until a newer key reports.
	rekeyUntil uint16
	reported   []uint16
	stamps     []time.Time
}

func (f *fakeHeartbeater) Heartbeat(keyIdx uint16, keyCreatedAt time.Time) (model.TKFSHeartbeatResponse, error) {
	f.reported = append(f.reported, keyIdx)
	f.stamps = append(f.stamps, keyCreatedAt)
	if f.laterErr != nil && len(f.reported) > 1 {
		return model.TKFSHeartbeatResponse{}, f.laterErr
	}
	if f.rekeyUntil > 0 {
		if keyIdx < f.rekeyUntil {
			return model.TKFSHeartbeatResponse{Command: model.TKFSCommandRekey}, f.err
		}
		return model.TKFSHeartbeatResponse{}, f.err
	}
	return f.answer, f.err
}

// assertReported checks the indices the beats reported, and that each came with its ring entry's stamp.
func assertReported(t *testing.T, dir string, hb *fakeHeartbeater, want []uint16) {
	t.Helper()
	if !slices.Equal(hb.reported, want) {
		t.Errorf("reported indices = %v, want %v", hb.reported, want)
	}
	kr := loadRing(t, dir)
	for i, idx := range hb.reported {
		if want := kr.Keys[idx].CreatedAt; !hb.stamps[i].Equal(want) {
			t.Errorf("beat %d reported index %d with stamp %v, want %v", i, idx, hb.stamps[i], want)
		}
	}
}

type fakeServer struct{ unmounts int }

func (f *fakeServer) Unmount() error {
	f.unmounts++
	return nil
}

// newTestMonitor wires a mounted monitor whose exit records the code instead of exiting; -1 means
// no exit. A nil hb leaves the monitor without a heartbeat.
func newTestMonitor(t *testing.T, r *keyRotator, hb *fakeHeartbeater) (m *keyServiceMonitor, srv *fakeServer, exitCode *int) {
	t.Helper()
	code := -1
	srv = &fakeServer{}
	m = &keyServiceMonitor{
		rotator:     r,
		opThreshold: defaultRotateOpThreshold,
		srv:         srv,
		exit:        func(c int) { code = c },
		stop:        make(chan struct{}),
	}
	if hb != nil {
		m.hb = hb
	}
	t.Cleanup(func() { fatalExitCode.Store(0) })
	return m, srv, &code
}

// A refusal is a decision about this instance and ends it at once; an outage is survivable twice.
func TestHeartbeatClassify(t *testing.T) {
	transport := errors.New("connection refused")
	denied := fmt.Errorf("gateway: %w", tkc.ErrDenied)

	t.Run("403 dies without waiting the count out", func(t *testing.T) {
		m := &keyServiceMonitor{}
		if die, _ := m.classify(denied); !die {
			t.Error("a 403 must end the mount")
		}
	})

	t.Run("third consecutive failure dies, not before", func(t *testing.T) {
		m := &keyServiceMonitor{}
		for i := 1; i < heartbeatFailureLimit; i++ {
			if die, _ := m.classify(transport); die {
				t.Fatalf("failure %d must not end the mount", i)
			}
		}
		die, reason := m.classify(transport)
		if !die {
			t.Errorf("failure %d must end the mount", heartbeatFailureLimit)
		}
		if !strings.Contains(reason, fmt.Sprintf("%d consecutive", heartbeatFailureLimit)) {
			t.Errorf("reason = %q, want the failure count", reason)
		}
	})

	t.Run("a success resets the counter", func(t *testing.T) {
		m := &keyServiceMonitor{}
		m.classify(transport)
		m.classify(transport)
		m.classify(nil)
		if die, _ := m.classify(transport); die {
			t.Error("the counter should have restarted")
		}
	})
}

// A gateway that cannot answer a heartbeat cannot revoke this instance either, so a beat that finds
// the route gone ends the mount rather than serving on with revocation quietly off.
func TestHeartbeatMissingRouteKills(t *testing.T) {
	m := &keyServiceMonitor{}
	die, reason := m.classify(fmt.Errorf("gateway: %w", tkc.ErrNotImplemented))
	if !die {
		t.Error("a missing route must end the mount")
	}
	if reason == "" {
		t.Error("a missing route should carry a reason to log")
	}
}

// A beat that dies unmounts and exits 33, or 35 when a gateway requiring binding refused -sharedstorage,
// as when the mount reaches such a gateway after starting behind another.
func TestHeartbeatRefusalUnmountsAndExits(t *testing.T) {
	for _, c := range []struct {
		err  error
		want int
	}{
		{fmt.Errorf("gateway: %w", tkc.ErrDenied), exitcodes.Revoked},
		{fmt.Errorf("gateway: %w", tkc.ErrSharedStorageRefused), exitcodes.SharedStorageRefused},
	} {
		hb := &fakeHeartbeater{err: c.err}
		r, _ := newTestRotator(t, "")
		m, srv, code := newTestMonitor(t, r, hb)
		m.beat()
		if *code != c.want {
			t.Errorf("%v: exit code = %d, want %d", c.err, *code, c.want)
		}
		if srv.unmounts != 1 {
			t.Errorf("%v: unmounts = %d, want 1", c.err, srv.unmounts)
		}
	}
}

// A rekey rotates, reports the new index at once, and every later beat reports the write index.
func TestHeartbeatRekeyRotatesAndReports(t *testing.T) {
	r, dir := newTestRotator(t, "")
	hb := &fakeHeartbeater{rekeyUntil: 1}
	m, srv, code := newTestMonitor(t, r, hb)

	m.beat()
	if n := len(loadRing(t, dir).Keys); n != 2 {
		t.Errorf("ring has %d entries after a rekey, want 2", n)
	}
	if got := r.cEnc.WriteKeyIdx(); got != 1 {
		t.Errorf("content write index = %d, want 1", got)
	}
	if got := r.nameTransform.WriteKeyIdx(); got != 1 {
		t.Errorf("name write index = %d, want 1", got)
	}
	m.beat()
	assertReported(t, dir, hb, []uint16{0, 1, 1})
	if *code != -1 || srv.unmounts != 0 {
		t.Errorf("exit code %d, %d unmounts; a rekey must not end the mount", *code, srv.unmounts)
	}
}

// One directive rotates at most rekeyRounds times, however long keep keeps asking.
func TestHeartbeatRekeyRoundsAreBounded(t *testing.T) {
	r, dir := newTestRotator(t, "")
	hb := &fakeHeartbeater{answer: model.TKFSHeartbeatResponse{Command: model.TKFSCommandRekey}}
	m, _, code := newTestMonitor(t, r, hb)
	m.beat()
	if n := len(loadRing(t, dir).Keys); n != rekeyRounds+1 {
		t.Errorf("ring has %d entries, want %d", n, rekeyRounds+1)
	}
	assertReported(t, dir, hb, []uint16{0, 1, 2, 3})
	if *code != -1 {
		t.Errorf("exit code = %d, want none", *code)
	}
}

// Mounts that both collect one directive satisfy it together with one new entry.
func TestHeartbeatRekeySeenByTwoMountsAddsOneEntry(t *testing.T) {
	a, dir := newTestRotator(t, "")
	b := mountTestRotator(t, dir)
	hbA, hbB := &fakeHeartbeater{rekeyUntil: 1}, &fakeHeartbeater{rekeyUntil: 1}
	ma, _, codeA := newTestMonitor(t, a, hbA)
	mb, _, codeB := newTestMonitor(t, b, hbB)
	var wg sync.WaitGroup
	for _, m := range []*keyServiceMonitor{ma, mb} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.rekey(0)
		}()
	}
	wg.Wait()
	if n := len(loadRing(t, dir).Keys); n != 2 {
		t.Errorf("ring has %d entries, want 2", n)
	}
	assertReported(t, dir, hbA, []uint16{1})
	assertReported(t, dir, hbB, []uint16{1})
	if *codeA != -1 || *codeB != -1 {
		t.Errorf("exit codes %d, %d; want none", *codeA, *codeB)
	}
}

// A mount that reports a stale index adopts the sibling's newer entry first; when that entry predates
// the directive, keep asks again and the next round adds one.
func TestHeartbeatRekeyAfterAdoptingAnOlderKey(t *testing.T) {
	a, dir := newTestRotator(t, "")
	b := mountTestRotator(t, dir)
	if _, err := a.rotate(rotateTrigger{manual: true}); err != nil {
		t.Fatal(err)
	}
	hb := &fakeHeartbeater{rekeyUntil: 2}
	m, _, code := newTestMonitor(t, b, hb)
	m.rekey(0)
	if n := len(loadRing(t, dir).Keys); n != 3 {
		t.Errorf("ring has %d entries, want 3", n)
	}
	assertReported(t, dir, hb, []uint16{1, 2})
	if *code != -1 {
		t.Errorf("exit code = %d, want none", *code)
	}
}

// Every beat reports the active entry's stamp from the key service, and a rotation by any trigger
// moves it with the index.
func TestHeartbeatReportsTheActiveKeysStamp(t *testing.T) {
	r, dir := newTestRotator(t, "")
	hb := &fakeHeartbeater{}
	m, _, _ := newTestMonitor(t, r, hb)
	m.beat()
	if _, err := r.rotate(rotateTrigger{manual: true}); err != nil {
		t.Fatal(err)
	}
	m.beat()
	assertReported(t, dir, hb, []uint16{0, 1})
}

// A beat reports the ring's head, learning a sibling's rotation first.
func TestHeartbeatReportsASiblingsRotation(t *testing.T) {
	a, dir := newTestRotator(t, "")
	b := mountTestRotator(t, dir)
	if _, err := a.rotate(rotateTrigger{manual: true}); err != nil {
		t.Fatal(err)
	}
	hb := &fakeHeartbeater{}
	m, _, _ := newTestMonitor(t, b, hb)
	m.beat()
	assertReported(t, dir, hb, []uint16{1})
}

// The report after a rekey is still a heartbeat: a refusal ends the mount, an outage does not.
func TestHeartbeatRekeyReportRefusalExits(t *testing.T) {
	for _, c := range []struct {
		name     string
		err      error
		wantCode int
	}{
		{"403", fmt.Errorf("gateway: %w", tkc.ErrDenied), exitcodes.Revoked},
		{"sharedstorage", fmt.Errorf("gateway: %w", tkc.ErrSharedStorageRefused), exitcodes.SharedStorageRefused},
		{"missing route", fmt.Errorf("gateway: %w", tkc.ErrNotImplemented), exitcodes.Revoked},
		{"outage", errors.New("connection refused"), -1},
	} {
		t.Run(c.name, func(t *testing.T) {
			hb := &fakeHeartbeater{answer: model.TKFSHeartbeatResponse{Command: model.TKFSCommandRekey}, laterErr: c.err}
			r, _ := newTestRotator(t, "")
			m, _, code := newTestMonitor(t, r, hb)
			m.beat()
			if *code != c.wantCode {
				t.Errorf("exit code = %d, want %d", *code, c.wantCode)
			}
			if m.failures != 0 {
				t.Errorf("failures = %d; a report must not spend the three-strike budget", m.failures)
			}
		})
	}
}

// An op count that cannot be persisted ends the mount with 36.
func TestMonitorOpCountPersistFailureExits(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores directory permissions")
	}
	r, dir := newTestRotator(t, "")
	m, srv, code := newTestMonitor(t, r, nil)
	ops := filepath.Dir(shardPath(dir, 0, r.mountID))
	if err := os.Chmod(ops, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(ops, 0700) })
	encrypt(r, 1)
	m.flushOpCounts()
	if *code != exitcodes.OpCountFailed {
		t.Errorf("exit code = %d, want %d", *code, exitcodes.OpCountFailed)
	}
	if srv.unmounts != 1 {
		t.Errorf("unmounts = %d, want 1", srv.unmounts)
	}
}

// A rekey whose rotation fails other than by a refusal ends the mount with 34.
func TestHeartbeatRekeyFailureExits(t *testing.T) {
	r, _ := newTestRotator(t, "not-this-instances-kek")
	hb := &fakeHeartbeater{answer: model.TKFSHeartbeatResponse{Command: model.TKFSCommandRekey}}
	m, srv, code := newTestMonitor(t, r, hb)
	m.beat()
	if *code != exitcodes.RotateFailed {
		t.Errorf("exit code = %d, want %d", *code, exitcodes.RotateFailed)
	}
	if srv.unmounts != 1 {
		t.Errorf("unmounts = %d, want 1", srv.unmounts)
	}
	if got := fatalExitCode.Load(); got != exitcodes.RotateFailed {
		t.Errorf("fatalExitCode = %d, want %d", got, exitcodes.RotateFailed)
	}
}

// -ro suppresses a rekey: rotating writes the key ring, and a read-only mount may not write the
// cipherdir. The directive stays pending for a writable mount.
func TestHeartbeatReadOnlyMountDoesNotRotate(t *testing.T) {
	r, dir := newTestRotator(t, "")
	hb := &fakeHeartbeater{answer: model.TKFSHeartbeatResponse{Command: model.TKFSCommandRekey}}
	m, _, code := newTestMonitor(t, r, hb)
	m.readOnly = true
	m.beat()
	if n := len(loadRing(t, dir).Keys); n != 1 {
		t.Errorf("a -ro mount rotated: ring has %d entries", n)
	}
	if *code != -1 {
		t.Errorf("exit code = %d, want none", *code)
	}
}

// A command this build does not know means carry on: the unambiguous "stop" is the 403.
func TestHeartbeatUnknownCommandDoesNotKill(t *testing.T) {
	r, dir := newTestRotator(t, "")
	hb := &fakeHeartbeater{answer: model.TKFSHeartbeatResponse{Command: "reticulate-splines"}}
	m, srv, code := newTestMonitor(t, r, hb)
	m.beat()
	if *code != -1 || srv.unmounts != 0 {
		t.Errorf("exit code %d, %d unmounts; an unrecognized command must not end the mount", *code, srv.unmounts)
	}
	if n := len(loadRing(t, dir).Keys); n != 1 {
		t.Errorf("ring has %d entries, want 1", n)
	}
}

// The pre-mount heartbeat refuses the mount on anything but an answer, and carries out a rekey
// before there is a mount to serve.
func TestVerifyKeyService(t *testing.T) {
	rekey := model.TKFSHeartbeatResponse{Command: model.TKFSCommandRekey}
	cases := []struct {
		name         string
		hb           fakeHeartbeater
		readOnly     bool
		wantCode     int
		wantKeys     int
		wantReported []uint16
	}{
		{"missing route", fakeHeartbeater{err: fmt.Errorf("gateway: %w", tkc.ErrNotImplemented)}, false, exitcodes.Revoked, 1, []uint16{0}},
		{"refused", fakeHeartbeater{err: fmt.Errorf("gateway: %w", tkc.ErrDenied)}, false, exitcodes.Revoked, 1, []uint16{0}},
		{"sharedstorage refused", fakeHeartbeater{err: fmt.Errorf("gateway: %w", tkc.ErrSharedStorageRefused)}, false,
			exitcodes.SharedStorageRefused, 1, []uint16{0}},
		{"unreachable", fakeHeartbeater{err: errors.New("connection refused")}, false, exitcodes.Revoked, 1, []uint16{0}},
		{"answered", fakeHeartbeater{}, false, -1, 1, []uint16{0}},
		{"rekey", fakeHeartbeater{rekeyUntil: 1}, false, -1, 2, []uint16{0, 1}},
		{"rekey on -ro", fakeHeartbeater{answer: rekey}, true, -1, 1, []uint16{0}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r, dir := newTestRotator(t, "")
			m, _, code := newTestMonitor(t, r, &c.hb)
			m.srv = nil
			m.readOnly = c.readOnly
			m.verifyKeyService()
			if *code != c.wantCode {
				t.Errorf("exit code = %d, want %d", *code, c.wantCode)
			}
			if n := len(loadRing(t, dir).Keys); n != c.wantKeys {
				t.Errorf("ring has %d entries, want %d", n, c.wantKeys)
			}
			assertReported(t, dir, &c.hb, c.wantReported)
		})
	}
}

// There is no value that turns auto-rotation off: zero is unset and a negative one is refused at
// parse time, so every path here lands on a real threshold.
func TestResolveRotateOpThreshold(t *testing.T) {
	if got := resolveRotateOpThreshold(0); got != defaultRotateOpThreshold {
		t.Errorf("0 = %d, want the default %d", got, defaultRotateOpThreshold)
	}
	if got := resolveRotateOpThreshold(-1); got != defaultRotateOpThreshold {
		t.Errorf("-1 = %d, want the default %d", got, defaultRotateOpThreshold)
	}
	if got := resolveRotateOpThreshold(1000); got != 1000 {
		t.Errorf("1000 = %d, want 1000", got)
	}
}

// The unmount flush stops the background loops, runs once, and leaves the rotator writing nothing
// and learning nothing afterwards.
func TestMonitorFlushOpCountsAtUnmountRunsOnce(t *testing.T) {
	a, dir := newTestRotator(t, "")
	b := mountTestRotator(t, dir)
	m, _, code := newTestMonitor(t, a, nil)
	done := make(chan struct{}, 2)
	go func() { m.run(); done <- struct{}{} }()
	go func() { m.watchRing(); done <- struct{}{} }()

	encrypt(a, 3)
	m.flushOpCountsAtUnmount()
	for range 2 {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("a monitor loop did not stop")
		}
	}
	if got := shardCount(t, dir, 0, a.mountID); got != 3 {
		t.Errorf("shard after the unmount flush = %d, want 3", got)
	}

	encrypt(a, 2)
	m.flushOpCountsAtUnmount()
	if _, _, err := a.flushOpCounts(1); err != nil {
		t.Fatal(err)
	}
	if got := shardCount(t, dir, 0, a.mountID); got != 3 {
		t.Errorf("shard = %d after a second unmount flush, want 3: nothing writes after the first", got)
	}
	if _, err := b.rotate(rotateTrigger{manual: true}); err != nil {
		t.Fatal(err)
	}
	if err := a.refresh(); err != nil {
		t.Fatal(err)
	}
	if err := a.cEnc.EnsureKey(1); err == nil {
		t.Error("a closed rotator learned a sibling's entry")
	}
	if *code != -1 {
		t.Errorf("exit code = %d, want none", *code)
	}
}

// watchRing learns a sibling's rotation within one refresh interval.
func TestMonitorWatchRingLearnsASiblingsRotation(t *testing.T) {
	if testing.Short() {
		t.Skip("waits a ring refresh interval")
	}
	a, dir := newTestRotator(t, "")
	b := mountTestRotator(t, dir)
	m, _, _ := newTestMonitor(t, a, nil)
	done := make(chan struct{})
	go func() { m.watchRing(); close(done) }()
	defer func() {
		close(m.stop)
		<-done
	}()
	idx, err := b.rotate(rotateTrigger{manual: true})
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(ringRefreshInterval + 5*time.Second)
	for a.cEnc.WriteKeyIdx() != idx {
		if time.Now().After(deadline) {
			t.Fatalf("write index = %d after %v, want %d", a.cEnc.WriteKeyIdx(), ringRefreshInterval, idx)
		}
		time.Sleep(100 * time.Millisecond)
	}
}
