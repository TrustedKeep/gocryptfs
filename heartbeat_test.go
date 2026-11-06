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
	// failFirst, if set, makes only the first failFirst beats answer err; later ones answer answer.
	failFirst int
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
	if f.failFirst > 0 && len(f.reported) > f.failFirst {
		return f.answer, nil
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

// The pre-mount heartbeat showed the key service has the route, so a 404/501 at runtime is a proxy, a
// load balancer or one node mid-deploy: an outage that spends the three-strike budget, not an unmount.
func TestHeartbeatMissingRouteIsAnOutage(t *testing.T) {
	m := &keyServiceMonitor{}
	missing := fmt.Errorf("gateway: %w", tkc.ErrNotImplemented)
	for i := 1; i < heartbeatFailureLimit; i++ {
		if die, _ := m.classify(missing); die {
			t.Fatalf("missing route %d must not end the mount", i)
		}
	}
	if die, reason := m.classify(missing); !die || reason == "" {
		t.Errorf("missing route %d must end the mount with a reason, got %v %q", heartbeatFailureLimit, die, reason)
	}
}

// Three failed beats in a row end the mount with 36, an outage a restart may get past, not 33, which
// a systemd unit is told never to restart.
func TestHeartbeatOutageExitsUnreachable(t *testing.T) {
	for _, err := range []error{errors.New("connection refused"), fmt.Errorf("gateway: %w", tkc.ErrNotImplemented)} {
		hb := &fakeHeartbeater{err: err}
		m, srv, code := newTestMonitor(t, newTestRotator(t, ""), hb)
		for i := 1; i < heartbeatFailureLimit; i++ {
			m.beat()
			if *code != -1 {
				t.Fatalf("%v: beat %d exited %d", err, i, *code)
			}
		}
		m.beat()
		if *code != exitcodes.KeyServiceUnreachable {
			t.Errorf("%v: exit code = %d, want %d", err, *code, exitcodes.KeyServiceUnreachable)
		}
		if srv.unmounts != 1 {
			t.Errorf("%v: unmounts = %d, want 1", err, srv.unmounts)
		}
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
		{"missing route", fmt.Errorf("gateway: %w", tkc.ErrNotImplemented), -1},
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

// failGenerate makes the rotator's key generation fail as an outage would, until the returned func is called.
func failGenerate(r *keyRotator) (restore func()) {
	r.generate = func() (tkc.TKFSDataKey, error) { return tkc.TKFSDataKey{}, errors.New("503 Service Unavailable") }
	return func() { r.generate = nil }
}

// A rekey whose rotation fails as an outage is retried: the directive stays pending, so each tick brings
// it back. Only heartbeatFailureLimit ticks in a row with a failure end the mount, with 34.
func TestHeartbeatRekeyOutageRetries(t *testing.T) {
	r := newTestRotator(t, "")
	failGenerate(r)
	hb := &fakeHeartbeater{answer: model.TKFSHeartbeatResponse{Command: model.TKFSCommandRekey}}
	m, srv, code := newTestMonitor(t, r, hb)
	for i := 1; i < heartbeatFailureLimit; i++ {
		m.tick()
		if *code != -1 || srv.unmounts != 0 {
			t.Fatalf("failed rotation %d ended the mount: code %d", i, *code)
		}
	}
	m.tick()
	if *code != exitcodes.RotateFailed {
		t.Errorf("exit code = %d, want %d", *code, exitcodes.RotateFailed)
	}
}

// A rotation that fails after the key service answered is not retried: here the key service wrapped the
// new key under a KEK other than this filesystem's, and a retry would only mint another.
func TestHeartbeatRekeyFailureExits(t *testing.T) {
	r := newTestRotator(t, "not-this-instances-kek")
	hb := &fakeHeartbeater{answer: model.TKFSHeartbeatResponse{Command: model.TKFSCommandRekey}}
	m, srv, code := newTestMonitor(t, r, hb)
	m.tick()
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
		// A missing route and an outage are retried; refusals are not.
		{"missing route", fakeHeartbeater{err: fmt.Errorf("gateway: %w", tkc.ErrNotImplemented)}, false, exitcodes.KeyServiceUnreachable, 1, []uint16{0, 0, 0, 0}},
		{"certificate rejected", fakeHeartbeater{err: fmt.Errorf("gateway: %w", tkc.ErrCertRejected)}, false, exitcodes.Revoked, 1, []uint16{0, 0, 0, 0}},
		// A rejected token is a decision, like a 403: not retried.
		{"token rejected", fakeHeartbeater{err: fmt.Errorf("search: %w", tkc.ErrUnauthenticated)}, false, exitcodes.Revoked, 1, []uint16{0}},
		{"refused", fakeHeartbeater{err: fmt.Errorf("gateway: %w", tkc.ErrDenied)}, false, exitcodes.Revoked, 1, []uint16{0}},
		{"sharedstorage refused", fakeHeartbeater{err: fmt.Errorf("gateway: %w", tkc.ErrSharedStorageRefused)}, false,
			exitcodes.SharedStorageRefused, 1, []uint16{0}},
		{"unreachable", fakeHeartbeater{err: errors.New("connection refused")}, false, exitcodes.KeyServiceUnreachable, 1, []uint16{0, 0, 0, 0}},
		{"recovers on a retry", fakeHeartbeater{err: errors.New("503"), failFirst: 2}, false, -1, 1, []uint16{0, 0, 0}},
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
			prevDelay := firstHeartbeatRetryDelay
			firstHeartbeatRetryDelay = 0
			t.Cleanup(func() { firstHeartbeatRetryDelay = prevDelay })
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

// A rotation the op counter demands is retried at the next flush on an outage, and only
// heartbeatFailureLimit failures in a row end the mount.
func TestFlushOpCountsRetriesAFailedRotation(t *testing.T) {
	r := newTestRotator(t, "")
	failGenerate(r)
	m, srv, code := newTestMonitor(t, r, nil)
	m.opThreshold = 1
	for i := 1; i <= heartbeatFailureLimit; i++ {
		r.cEnc.EncryptBlock(make([]byte, 16), 0, nil, r.cEnc.WriteKeyIdx())
		m.tick()
		if i < heartbeatFailureLimit && (*code != -1 || srv.unmounts != 0) {
			t.Fatalf("failed rotation %d ended the mount: code %d", i, *code)
		}
	}
	if *code != exitcodes.RotateFailed {
		t.Errorf("exit code = %d, want %d", *code, exitcodes.RotateFailed)
	}
}

// A refusal during a demanded rotation still ends the mount at once.
func TestRotationRefusalEndsTheMount(t *testing.T) {
	m, srv, code := newTestMonitor(t, newTestRotator(t, ""), nil)
	m.rotationFailed("rekey", fmt.Errorf("gateway: %w", tkc.ErrDenied))
	if *code != exitcodes.Revoked || srv.unmounts != 1 {
		t.Errorf("exit code %d, %d unmounts; want %d and 1", *code, srv.unmounts, exitcodes.Revoked)
	}
}

// A filesystem made with the mock key store mounts only when the mount command asks for the mock too.
func TestCheckMockKMS(t *testing.T) {
	if err := checkMockKMS(false, false); err != nil {
		t.Errorf("a real key store: %v", err)
	}
	if err := checkMockKMS(true, false); err == nil {
		t.Error("a mock config without -mock-kms must be refused")
	}
	if err := checkMockKMS(true, true); err != nil {
		t.Errorf("a mock config with -mock-kms: %v", err)
	}
}

// A rekey and the op counter failing in the same tick are one strike, not two.
func TestRotationFailuresCountOncePerTick(t *testing.T) {
	r := newTestRotator(t, "")
	failGenerate(r)
	hb := &fakeHeartbeater{answer: model.TKFSHeartbeatResponse{Command: model.TKFSCommandRekey}}
	m, _, code := newTestMonitor(t, r, hb)
	m.opThreshold = 1
	for i := 1; i < heartbeatFailureLimit; i++ {
		r.cEnc.EncryptBlock(make([]byte, 16), 0, nil, r.cEnc.WriteKeyIdx())
		m.tick()
		if *code != -1 {
			t.Fatalf("tick %d ended the mount with %d; both failures in one tick are one strike", i, *code)
		}
	}
	if m.rotateFailures != heartbeatFailureLimit-1 {
		t.Errorf("rotateFailures = %d, want %d", m.rotateFailures, heartbeatFailureLimit-1)
	}
}

// A tick with no failed rotation, such as after a -ctlsock Rotate settled what was demanded, clears the
// count, so a later outage starts a fresh three strikes.
func TestRotationFailureCountResetsWhenNothingFails(t *testing.T) {
	r := newTestRotator(t, "")
	restore := failGenerate(r)
	hb := &fakeHeartbeater{answer: model.TKFSHeartbeatResponse{Command: model.TKFSCommandRekey}}
	m, _, code := newTestMonitor(t, r, hb)
	m.tick()
	m.tick()
	hb.answer = model.TKFSHeartbeatResponse{}
	m.tick()
	if m.rotateFailures != 0 {
		t.Fatalf("rotateFailures = %d after a quiet tick, want 0", m.rotateFailures)
	}
	hb.answer = model.TKFSHeartbeatResponse{Command: model.TKFSCommandRekey}
	m.tick()
	if *code != -1 {
		t.Errorf("one new failure after the reset ended the mount with %d", *code)
	}
	restore()
}

// A rekey the pre-mount heartbeat brings back is carried out before anything is served, so failing it
// ends the mount even when it is an outage.
func TestVerifyKeyServiceRekeyFailureIsFatal(t *testing.T) {
	r := newTestRotator(t, "")
	failGenerate(r)
	hb := &fakeHeartbeater{answer: model.TKFSHeartbeatResponse{Command: model.TKFSCommandRekey}}
	m, _, code := newTestMonitor(t, r, hb)
	m.srv = nil
	m.verifyKeyService()
	if *code != exitcodes.RotateFailed {
		t.Errorf("exit code = %d, want %d", *code, exitcodes.RotateFailed)
	}
}

// A mount that dies of failures that were the key service rejecting its credentials exits as revoked,
// which a systemd unit does not restart; any other outage exits 36, which it does.
func TestOutageExit(t *testing.T) {
	for _, c := range []struct {
		err  error
		want int
	}{
		{errors.New("connection refused"), exitcodes.KeyServiceUnreachable},
		{fmt.Errorf("gateway: %w", tkc.ErrNotImplemented), exitcodes.KeyServiceUnreachable},
		{fmt.Errorf("gateway: %w", tkc.ErrCertRejected), exitcodes.Revoked},
		// Text alone is not a rejection: a 5xx body can quote an upstream TLS failure.
		{errors.New(`HTTP 502: dial upstream: remote error: tls: bad certificate`), exitcodes.KeyServiceUnreachable},
		{fmt.Errorf("search: not authorized (HTTP 401): %w", tkc.ErrUnauthenticated), exitcodes.Revoked},
	} {
		if got := outageExit(c.err); got != c.want {
			t.Errorf("outageExit(%v) = %d, want %d", c.err, got, c.want)
		}
	}
}

// The pre-mount retries stop once another wait would pass firstHeartbeatBudget, however many attempts
// are left, so a slow key service cannot hold the mount past systemd's start timeout.
func TestFirstHeartbeatStopsAtItsBudget(t *testing.T) {
	prevDelay, prevBudget := firstHeartbeatRetryDelay, firstHeartbeatBudget
	firstHeartbeatRetryDelay, firstHeartbeatBudget = time.Millisecond, 0
	t.Cleanup(func() { firstHeartbeatRetryDelay, firstHeartbeatBudget = prevDelay, prevBudget })
	hb := &fakeHeartbeater{err: errors.New("connection refused")}
	m, _, code := newTestMonitor(t, newTestRotator(t, ""), hb)
	m.srv = nil
	m.verifyKeyService()
	if len(hb.reported) != 1 {
		t.Errorf("attempts = %d, want 1 once the budget is spent", len(hb.reported))
	}
	if *code != exitcodes.KeyServiceUnreachable {
		t.Errorf("exit code = %d, want %d", *code, exitcodes.KeyServiceUnreachable)
	}
}

// A tick whose heartbeat failed clears nothing: it could not learn whether the rekey is still pending,
// so a key service alternating failed beats and failed rotations still reaches three strikes.
func TestFailedHeartbeatDoesNotClearRotationFailures(t *testing.T) {
	r := newTestRotator(t, "")
	failGenerate(r)
	rekey := model.TKFSHeartbeatResponse{Command: model.TKFSCommandRekey}
	hb := &fakeHeartbeater{answer: rekey}
	m, _, code := newTestMonitor(t, r, hb)
	for i := 1; i <= heartbeatFailureLimit; i++ {
		hb.err = nil
		m.tick() // heartbeat answers, rotation fails
		if i == heartbeatFailureLimit {
			break
		}
		hb.err = errors.New("connection refused")
		m.tick() // heartbeat fails: must not clear the rotation strikes
	}
	if *code != exitcodes.RotateFailed {
		t.Errorf("exit code = %d, want %d after %d failed rotations between failed beats",
			*code, exitcodes.RotateFailed, heartbeatFailureLimit)
	}
}

// Before mounting, a key already past its op budget must not start serving, so a failed rotation ends
// the mount even as an outage.
func TestFlushOpCountsBeforeMountRotationFailureIsFatal(t *testing.T) {
	r := newTestRotator(t, "")
	failGenerate(r)
	m, _, code := newTestMonitor(t, r, nil)
	m.srv = nil
	m.opThreshold = 1
	r.cEnc.EncryptBlock(make([]byte, 16), 0, nil, r.cEnc.WriteKeyIdx())
	m.flushOpCountsBeforeMount()
	if *code != exitcodes.RotateFailed {
		t.Errorf("exit code = %d, want %d", *code, exitcodes.RotateFailed)
	}
}
