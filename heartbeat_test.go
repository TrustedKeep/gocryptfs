package main

import (
	"crypto/cipher"
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
	"github.com/rfjakob/eme"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/internal/tkc"
)

// testNodeID names this process's mock key store.
var testNodeID = fmt.Sprintf("gocryptfs-main-test-%d", os.Getpid())

var connectOnce sync.Once

func TestMain(m *testing.M) {
	r := m.Run()
	os.Remove(filepath.Join(os.TempDir(), "tkfs_mock_gateway_"+testNodeID+".db"))
	os.Exit(r)
}

// newTestRotator returns a rotator over a one-entry ring in a temp dir, backed by the mock key service.
// A non-empty keyID overrides the entry's KEK, which makes every rotation fail.
func newTestRotator(t *testing.T, keyID string) *keyRotator {
	t.Helper()
	connectOnce.Do(func() { tkc.Connect("", "", testNodeID, true, false, false, false) })
	dk, err := tkc.DataKey().GenerateTKFSDataKey()
	if err != nil {
		t.Fatal(err)
	}
	if keyID == "" {
		keyID = dk.KeyID
	}
	conf := filepath.Join(t.TempDir(), configfile.ConfDefaultName)
	kr, err := configfile.LoadKeyRing(conf)
	if err != nil {
		t.Fatal(err)
	}
	kr.Append(configfile.KeyRingEntry{KeyID: keyID, Ciphertext: dk.Ciphertext, CreatedAt: dk.CreatedAt})
	if err := kr.WriteFile(); err != nil {
		t.Fatal(err)
	}
	core := cryptocore.New(dk.Plaintext, cryptocore.BackendGoGCM, contentenc.DefaultIVBits)
	r, err := newKeyRotator(conf, kr, cryptocore.BackendGoGCM, contentenc.DefaultIVBits,
		contentenc.New(core, []cipher.AEAD{core.AEADCipher}, contentenc.DefaultBS),
		nametransform.New([]*eme.EMECipher{core.EMECipher}, false, 0, false, nil, false))
	if err != nil {
		t.Fatal(err)
	}
	return r
}

// loadRing reads back the rotator's ring from disk.
func loadRing(t *testing.T, r *keyRotator) *configfile.KeyRing {
	t.Helper()
	kr, err := configfile.LoadKeyRing(r.configPath)
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
	reported []uint16
	stamps   []time.Time
}

func (f *fakeHeartbeater) Heartbeat(keyIdx uint16, keyCreatedAt time.Time) (model.TKFSHeartbeatResponse, error) {
	f.reported = append(f.reported, keyIdx)
	f.stamps = append(f.stamps, keyCreatedAt)
	if f.laterErr != nil && len(f.reported) > 1 {
		return model.TKFSHeartbeatResponse{}, f.laterErr
	}
	return f.answer, f.err
}

// assertReported checks the indices the beats reported, and that each came with its ring entry's stamp.
func assertReported(t *testing.T, r *keyRotator, hb *fakeHeartbeater, want []uint16) {
	t.Helper()
	if !slices.Equal(hb.reported, want) {
		t.Errorf("reported indices = %v, want %v", hb.reported, want)
	}
	kr := loadRing(t, r)
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
		m, srv, code := newTestMonitor(t, newTestRotator(t, ""), hb)
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
	r := newTestRotator(t, "")
	hb := &fakeHeartbeater{answer: model.TKFSHeartbeatResponse{Command: model.TKFSCommandRekey}}
	m, srv, code := newTestMonitor(t, r, hb)

	m.beat()
	if n := len(loadRing(t, r).Keys); n != 2 {
		t.Errorf("ring has %d entries after a rekey, want 2", n)
	}
	if got := r.cEnc.WriteKeyIdx(); got != 1 {
		t.Errorf("content write index = %d, want 1", got)
	}
	if got := r.nameTransform.WriteKeyIdx(); got != 1 {
		t.Errorf("name write index = %d, want 1", got)
	}
	hb.answer = model.TKFSHeartbeatResponse{}
	m.beat()
	assertReported(t, r, hb, []uint16{0, 1, 1})
	if *code != -1 || srv.unmounts != 0 {
		t.Errorf("exit code %d, %d unmounts; a rekey must not end the mount", *code, srv.unmounts)
	}
}

// Every beat reports the active entry's stamp from the key service, and a rotation by any trigger
// moves it with the index.
func TestHeartbeatReportsTheActiveKeysStamp(t *testing.T) {
	r := newTestRotator(t, "")
	hb := &fakeHeartbeater{}
	m, _, _ := newTestMonitor(t, r, hb)
	m.beat()
	if _, err := r.rotate(); err != nil {
		t.Fatal(err)
	}
	m.beat()
	assertReported(t, r, hb, []uint16{0, 1})
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
			m, _, code := newTestMonitor(t, newTestRotator(t, ""), hb)
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

// A rekey whose rotation fails other than by a refusal ends the mount with 34.
func TestHeartbeatRekeyFailureExits(t *testing.T) {
	r := newTestRotator(t, "not-this-instances-kek")
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
	r := newTestRotator(t, "")
	hb := &fakeHeartbeater{answer: model.TKFSHeartbeatResponse{Command: model.TKFSCommandRekey}}
	m, _, code := newTestMonitor(t, r, hb)
	m.readOnly = true
	m.beat()
	if n := len(loadRing(t, r).Keys); n != 1 {
		t.Errorf("a -ro mount rotated: ring has %d entries", n)
	}
	if *code != -1 {
		t.Errorf("exit code = %d, want none", *code)
	}
}

// A command this build does not know means carry on: the unambiguous "stop" is the 403.
func TestHeartbeatUnknownCommandDoesNotKill(t *testing.T) {
	r := newTestRotator(t, "")
	hb := &fakeHeartbeater{answer: model.TKFSHeartbeatResponse{Command: "reticulate-splines"}}
	m, srv, code := newTestMonitor(t, r, hb)
	m.beat()
	if *code != -1 || srv.unmounts != 0 {
		t.Errorf("exit code %d, %d unmounts; an unrecognized command must not end the mount", *code, srv.unmounts)
	}
	if n := len(loadRing(t, r).Keys); n != 1 {
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
		{"rekey", fakeHeartbeater{answer: rekey}, false, -1, 2, []uint16{0, 1}},
		{"rekey on -ro", fakeHeartbeater{answer: rekey}, true, -1, 1, []uint16{0}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := newTestRotator(t, "")
			m, _, code := newTestMonitor(t, r, &c.hb)
			m.srv = nil
			m.readOnly = c.readOnly
			m.verifyKeyService()
			if *code != c.wantCode {
				t.Errorf("exit code = %d, want %d", *code, c.wantCode)
			}
			if n := len(loadRing(t, r).Keys); n != c.wantKeys {
				t.Errorf("ring has %d entries, want %d", n, c.wantKeys)
			}
			assertReported(t, r, &c.hb, c.wantReported)
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
