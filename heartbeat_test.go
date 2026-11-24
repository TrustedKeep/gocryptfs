package main

import (
	"crypto/cipher"
	"errors"
	"fmt"
	"maps"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/TrustedKeep/tkutils/v2/model"
	"github.com/hanwen/go-fuse/v2/fuse"
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
	events   []model.TKFSHeartbeatEvent
	// block, if set, holds every beat until it is closed.
	block chan struct{}
	// eventErr, if set, answers a beat carrying that event with its error.
	eventErr map[model.TKFSHeartbeatEvent]error
}

func (f *fakeHeartbeater) Heartbeat(event model.TKFSHeartbeatEvent, keyIdx uint16, keyCreatedAt time.Time) (model.TKFSHeartbeatResponse, error) {
	if f.block != nil {
		<-f.block
	}
	f.events = append(f.events, event)
	f.reported = append(f.reported, keyIdx)
	f.stamps = append(f.stamps, keyCreatedAt)
	if err, ok := f.eventErr[event]; ok {
		return model.TKFSHeartbeatResponse{}, err
	}
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

// newTestMonitor wires a monitor whose exit records the code instead of exiting; -1 means no exit. A
// nil hb leaves the monitor without a heartbeat.
func newTestMonitor(t *testing.T, r *keyRotator, hb *fakeHeartbeater) (m *keyServiceMonitor, exitCode *int) {
	t.Helper()
	code := -1
	m = &keyServiceMonitor{
		gate:        new(keyGate),
		rotator:     r,
		opThreshold: defaultRotateOpThreshold,
		exit:        func(c int) { code = c },
	}
	if hb != nil {
		m.hb = hb
	}
	return m, &code
}

// assertServing fails unless the monitor has not exited and its file operations are suspended or not, as wanted.
func assertServing(t *testing.T, m *keyServiceMonitor, code *int, wantSuspended bool) {
	t.Helper()
	if *code != -1 {
		t.Errorf("exit code = %d; a running mount must never exit", *code)
	}
	if got := m.gate.suspended.Load(); got != wantSuspended {
		t.Errorf("suspended = %v, want %v", got, wantSuspended)
	}
}

// A refusal suspends at once; an outage only on its heartbeatFailureLimit-th time in a row. Either way
// the next answered beat resumes.
func TestHeartbeatSuspension(t *testing.T) {
	for _, c := range []struct {
		name    string
		err     error
		strikes int
	}{
		{"403", fmt.Errorf("gateway: %w", tkc.ErrDenied), 1},
		{"sharedstorage refused", fmt.Errorf("gateway: %w", tkc.ErrSharedStorageRefused), 1},
		{"outage", errors.New("connection refused"), heartbeatFailureLimit},
		// The pre-mount heartbeat showed the route exists, so now a 404 is a proxy or a deploy.
		{"missing route", fmt.Errorf("gateway: %w", tkc.ErrNotImplemented), heartbeatFailureLimit},
		{"certificate rejected", fmt.Errorf("gateway: %w", tkc.ErrCertRejected), heartbeatFailureLimit},
	} {
		t.Run(c.name, func(t *testing.T) {
			hb := &fakeHeartbeater{err: c.err}
			m, code := newTestMonitor(t, newTestRotator(t, ""), hb)
			for i := 1; i < c.strikes; i++ {
				m.tick()
				assertServing(t, m, code, false)
			}
			m.tick()
			assertServing(t, m, code, true)
			hb.err = nil
			m.tick()
			assertServing(t, m, code, false)
		})
	}
}

// A suspended mount stays suspended through a tick whose heartbeat answers until that tick's rotations
// have run, so a rekey that then fails never sees the gate open.
func TestHeartbeatResumesOnlyAtTheEndOfATick(t *testing.T) {
	r := newTestRotator(t, "")
	hb := &fakeHeartbeater{err: fmt.Errorf("gateway: %w", tkc.ErrDenied)}
	m, code := newTestMonitor(t, r, hb)
	m.tick()
	assertServing(t, m, code, true)

	var openDuringRekey bool
	r.generate = func() (tkc.TKFSDataKey, error) {
		openDuringRekey = !m.gate.suspended.Load()
		return tkc.TKFSDataKey{}, errors.New("503 Service Unavailable")
	}
	hb.err = nil
	hb.answer = model.TKFSHeartbeatResponse{Command: model.TKFSCommandRekey}
	m.tick()
	if openDuringRekey {
		t.Error("file operations reopened before the tick's rekey ran")
	}
	assertServing(t, m, code, false)
}

// Resuming reports a mount, which stamps the record's LastMounted, and a refusal of that report keeps the
// mount suspended.
func TestResumeReportsAMount(t *testing.T) {
	denied := fmt.Errorf("gateway: %w", tkc.ErrDenied)
	hb := &fakeHeartbeater{err: denied}
	m, code := newTestMonitor(t, newTestRotator(t, ""), hb)
	m.tick()
	hb.err = nil
	m.tick()
	assertServing(t, m, code, false)
	want := []model.TKFSHeartbeatEvent{model.TKFSEventNone, model.TKFSEventNone, model.TKFSEventMount}
	if !slices.Equal(hb.events, want) {
		t.Errorf("events = %v, want %v", hb.events, want)
	}

	hb.err = denied
	m.tick()
	hb.err = nil
	hb.eventErr = map[model.TKFSHeartbeatEvent]error{model.TKFSEventMount: denied}
	m.tick()
	assertServing(t, m, code, true)
}

type fakeCtl struct{}

func (fakeCtl) EncryptPath(p string) (string, error) { return "enc:" + p, nil }
func (fakeCtl) DecryptPath(p string) (string, error) { return "dec:" + p, nil }

// The control socket's path translation is refused while suspended, with an errno it can report.
func TestGatedCtl(t *testing.T) {
	if _, ok := gateCtl(fakeCtl{}, nil).(fakeCtl); !ok {
		t.Error("with no gate, the control socket must not be wrapped")
	}
	var gate keyGate
	g := gateCtl(fakeCtl{}, &gate)
	for name, f := range map[string]func(string) (string, error){"EncryptPath": g.EncryptPath, "DecryptPath": g.DecryptPath} {
		if out, err := f("a/b"); err != nil || out == "" {
			t.Errorf("%s while open = %q, %v; want it passed through", name, out, err)
		}
		gate.suspended.Store(true)
		out, err := f("a/b")
		var pe *os.PathError
		if out != "" || !errors.As(err, &pe) || pe.Err != suspendedErrno {
			t.Errorf("%s while suspended = %q, %v; want a *os.PathError with %v", name, out, err, suspendedErrno)
		}
		gate.suspended.Store(false)
	}
}

// An outage after a refusal is no answer, so it must not resume a refused mount.
func TestHeartbeatOutageDoesNotLiftARefusal(t *testing.T) {
	hb := &fakeHeartbeater{err: fmt.Errorf("gateway: %w", tkc.ErrDenied)}
	m, code := newTestMonitor(t, newTestRotator(t, ""), hb)
	m.tick()
	hb.err = errors.New("connection refused")
	m.tick()
	assertServing(t, m, code, true)
}

// A success resets the outage count, so the next outage starts a fresh three strikes.
func TestHeartbeatSuccessResetsTheCount(t *testing.T) {
	hb := &fakeHeartbeater{}
	m, code := newTestMonitor(t, newTestRotator(t, ""), hb)
	for _, err := range []error{errors.New("x"), errors.New("x"), nil, errors.New("x"), errors.New("x")} {
		hb.err = err
		m.tick()
	}
	assertServing(t, m, code, false)
}

// Each gated operation fails while suspended and passes through otherwise. A RawFileSystem method this
// test does not know fails it until it is gated or listed as ungated.
func TestGatedFS(t *testing.T) {
	ungated := map[string]bool{
		"String": true, "SetDebug": true, "Init": true, "OnUnmount": true, "Forget": true,
		"GetLk": true, "SetLk": true, "SetLkw": true, "Ioctl": true,
		"Release": true, "ReleaseDir": true, "Flush": true, "Fsync": true, "FsyncDir": true,
	}
	var gate keyGate
	var isIdle atomic.Bool
	g := reflect.ValueOf(&gatedFS{RawFileSystem: fuse.NewDefaultRawFileSystem(), gate: &gate, isIdle: &isIdle})
	rawFS := reflect.TypeOf((*fuse.RawFileSystem)(nil)).Elem()
	for i := 0; i < rawFS.NumMethod(); i++ {
		name := rawFS.Method(i).Name
		if ungated[name] {
			continue
		}
		method := g.MethodByName(name)
		call := func() fuse.Status {
			args := make([]reflect.Value, method.Type().NumIn())
			for j := range args {
				if in := method.Type().In(j); in.Kind() == reflect.Pointer {
					args[j] = reflect.New(in.Elem())
				} else {
					args[j] = reflect.Zero(in)
				}
			}
			out := method.Call(args)
			return out[len(out)-1].Interface().(fuse.Status)
		}
		gate.suspended.Store(true)
		isIdle.Store(true)
		if got := call(); got != suspendedStatus {
			t.Errorf("%s while suspended = %v, want %v; gate it, or list it as ungated", name, got, suspendedStatus)
		}
		if isIdle.Load() {
			t.Errorf("%s refused without marking the filesystem busy, so -idle would unmount it", name)
		}
		gate.suspended.Store(false)
		if got := call(); got == suspendedStatus {
			t.Errorf("%s while open = %v, want it passed through", name, got)
		}
	}
}

// openFS opens, creates and releases every node but failNode, calling during, if set, inside each open.
type openFS struct {
	fuse.RawFileSystem
	during func()
}

const failNode = 99

func (f *openFS) Open(_ <-chan struct{}, in *fuse.OpenIn, _ *fuse.OpenOut) fuse.Status {
	if f.during != nil {
		f.during()
	}
	if in.NodeId == failNode {
		return fuse.ENOENT
	}
	return fuse.OK
}

func (*openFS) Create(<-chan struct{}, *fuse.CreateIn, string, *fuse.CreateOut) fuse.Status {
	return fuse.OK
}
func (*openFS) Tmpfile(<-chan struct{}, *fuse.CreateIn, *fuse.CreateOut) fuse.Status { return fuse.OK }
func (*openFS) Release(<-chan struct{}, *fuse.ReleaseIn)                             {}

// dropRecorder records the nodes a keyGate drops, which it does on goroutines of their own.
type dropRecorder chan uint64

func (d dropRecorder) invalidate(node uint64, off, length int64) fuse.Status {
	if off != 0 || length != 0 {
		panic(fmt.Sprintf("node %d dropped from %d for %d bytes, want the whole file", node, off, length))
	}
	d <- node
	return fuse.OK
}

// next waits for n drops and returns their nodes.
func (d dropRecorder) next(t *testing.T, n int) map[uint64]bool {
	t.Helper()
	got := map[uint64]bool{}
	for range n {
		select {
		case node := <-d:
			got[node] = true
		case <-time.After(5 * time.Second):
			t.Fatalf("only %d of %d drops came: %v", len(got), n, got)
		}
	}
	return got
}

// none fails if anything was dropped, giving stray drops a moment to land.
func (d dropRecorder) none(t *testing.T, when string) {
	t.Helper()
	select {
	case node := <-d:
		t.Errorf("%s dropped the pages of node %d", when, node)
	case <-time.After(50 * time.Millisecond):
	}
}

// Suspending drops the cached pages of every file still open, once, and resuming drops none. An open the
// gate closed under drops its own.
func TestSuspensionDropsCachedPages(t *testing.T) {
	hb := &fakeHeartbeater{err: fmt.Errorf("gateway: %w", tkc.ErrDenied)}
	m, code := newTestMonitor(t, newTestRotator(t, ""), hb)
	dropped := make(dropRecorder, 16)
	m.gate.invalidate = dropped.invalidate
	fs := &openFS{RawFileSystem: fuse.NewDefaultRawFileSystem()}
	g := &gatedFS{RawFileSystem: fs, gate: m.gate}
	open := func(node uint64) { g.Open(nil, &fuse.OpenIn{InHeader: fuse.InHeader{NodeId: node}}, &fuse.OpenOut{}) }
	release := func(node uint64) { g.Release(nil, &fuse.ReleaseIn{InHeader: fuse.InHeader{NodeId: node}}) }
	open(5)
	open(5)
	release(5)
	open(6)
	release(6)
	open(failNode)
	g.Create(nil, &fuse.CreateIn{}, "c", &fuse.CreateOut{EntryOut: fuse.EntryOut{NodeId: 7}})
	g.Tmpfile(nil, &fuse.CreateIn{}, &fuse.CreateOut{EntryOut: fuse.EntryOut{NodeId: 8}})
	want := map[uint64]bool{5: true, 7: true, 8: true}

	m.tick()
	assertServing(t, m, code, true)
	if got := dropped.next(t, len(want)); !maps.Equal(got, want) {
		t.Errorf("suspending dropped the pages of %v, want %v", got, want)
	}
	open(9)
	m.tick()
	dropped.none(t, "a tick that stayed suspended")

	hb.err = nil
	m.tick()
	assertServing(t, m, code, false)
	dropped.none(t, "resuming")

	fs.during = func() { m.setSuspended(true) }
	open(10)
	want[10] = true
	if got := dropped.next(t, len(want)); !maps.Equal(got, want) {
		t.Errorf("suspending during an open dropped the pages of %v, want %v", got, want)
	}
}

// A drop stuck behind a hung read holds back neither the other files nor the monitor.
func TestSuspensionDoesNotWaitOnAStuckDrop(t *testing.T) {
	m, _ := newTestMonitor(t, newTestRotator(t, ""), nil)
	stuck := make(chan struct{})
	defer close(stuck)
	dropped := make(dropRecorder, 16)
	m.gate.invalidate = func(node uint64, off, length int64) fuse.Status {
		if node == 1 {
			<-stuck
		}
		return dropped.invalidate(node, off, length)
	}
	m.gate.opened(1)
	m.gate.opened(2)
	done := make(chan struct{})
	go func() {
		m.setSuspended(true)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("suspending waited on a stuck drop")
	}
	if got := dropped.next(t, 1); !got[2] {
		t.Errorf("with node 1 stuck, dropped %v, want node 2", got)
	}
}

// Writeback of pages dirtied through a mapping passes the gate: refusing it would only discard them.
func TestGatedFSLetsWritebackThrough(t *testing.T) {
	g := &gatedFS{RawFileSystem: fuse.NewDefaultRawFileSystem(), gate: new(keyGate)}
	g.gate.suspended.Store(true)
	writes := map[string]func(*fuse.WriteIn) fuse.Status{
		"Write":  func(in *fuse.WriteIn) fuse.Status { _, st := g.Write(nil, in, nil); return st },
		"Writev": func(in *fuse.WriteIn) fuse.Status { _, st := g.Writev(nil, in, nil); return st },
	}
	for name, write := range writes {
		if st := write(&fuse.WriteIn{WriteFlags: fuse.WRITE_CACHE}); st == suspendedStatus {
			t.Errorf("%s of a writeback while suspended = %v, want it passed through", name, st)
		}
		if st := write(&fuse.WriteIn{}); st != suspendedStatus {
			t.Errorf("%s while suspended = %v, want %v", name, st, suspendedStatus)
		}
	}
}

// A rekey rotates, reports the new index at once, and every later beat reports the write index.
func TestHeartbeatRekeyRotatesAndReports(t *testing.T) {
	r := newTestRotator(t, "")
	hb := &fakeHeartbeater{answer: model.TKFSHeartbeatResponse{Command: model.TKFSCommandRekey}}
	m, code := newTestMonitor(t, r, hb)

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
	assertServing(t, m, code, false)
}

// Every beat reports the active entry's stamp from the key service, and a rotation by any trigger
// moves it with the index.
func TestHeartbeatReportsTheActiveKeysStamp(t *testing.T) {
	r := newTestRotator(t, "")
	hb := &fakeHeartbeater{}
	m, _ := newTestMonitor(t, r, hb)
	m.beat()
	if _, err := r.rotate(); err != nil {
		t.Fatal(err)
	}
	m.beat()
	assertReported(t, r, hb, []uint16{0, 1})
}

// The report after a rekey is still a heartbeat: a refusal suspends, an outage does not.
func TestHeartbeatRekeyReportRefusalSuspends(t *testing.T) {
	for _, c := range []struct {
		name          string
		err           error
		wantSuspended bool
	}{
		{"403", fmt.Errorf("gateway: %w", tkc.ErrDenied), true},
		{"sharedstorage", fmt.Errorf("gateway: %w", tkc.ErrSharedStorageRefused), true},
		{"missing route", fmt.Errorf("gateway: %w", tkc.ErrNotImplemented), false},
		{"outage", errors.New("connection refused"), false},
	} {
		t.Run(c.name, func(t *testing.T) {
			hb := &fakeHeartbeater{answer: model.TKFSHeartbeatResponse{Command: model.TKFSCommandRekey}, laterErr: c.err}
			m, code := newTestMonitor(t, newTestRotator(t, ""), hb)
			m.beat()
			assertServing(t, m, code, c.wantSuspended)
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
// it back. heartbeatFailureLimit ticks in a row with a failure suspend, and a tick that rotates resumes.
func TestHeartbeatRekeyOutageRetries(t *testing.T) {
	r := newTestRotator(t, "")
	restore := failGenerate(r)
	hb := &fakeHeartbeater{answer: model.TKFSHeartbeatResponse{Command: model.TKFSCommandRekey}}
	m, code := newTestMonitor(t, r, hb)
	for i := 1; i < heartbeatFailureLimit; i++ {
		m.tick()
		assertServing(t, m, code, false)
	}
	m.tick()
	assertServing(t, m, code, true)
	restore()
	m.tick()
	assertServing(t, m, code, false)
	if n := len(loadRing(t, r).Keys); n != 2 {
		t.Errorf("ring has %d entries, want 2", n)
	}
}

// A rotation that fails after the key service answered suspends at once: here the key service wrapped
// the new key under a KEK other than this filesystem's.
func TestHeartbeatRekeyFatalFailureSuspends(t *testing.T) {
	r := newTestRotator(t, "not-this-instances-kek")
	hb := &fakeHeartbeater{answer: model.TKFSHeartbeatResponse{Command: model.TKFSCommandRekey}}
	m, code := newTestMonitor(t, r, hb)
	m.tick()
	assertServing(t, m, code, true)
}

// -ro suppresses a rekey: rotating writes the key ring, and a read-only mount may not write the
// cipherdir. The directive stays pending for a writable mount.
func TestHeartbeatReadOnlyMountDoesNotRotate(t *testing.T) {
	r := newTestRotator(t, "")
	hb := &fakeHeartbeater{answer: model.TKFSHeartbeatResponse{Command: model.TKFSCommandRekey}}
	m, code := newTestMonitor(t, r, hb)
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
	m, code := newTestMonitor(t, r, hb)
	m.beat()
	assertServing(t, m, code, false)
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
			m, code := newTestMonitor(t, r, &c.hb)
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
// heartbeatFailureLimit failures in a row suspend.
func TestFlushOpCountsRetriesAFailedRotation(t *testing.T) {
	r := newTestRotator(t, "")
	failGenerate(r)
	m, code := newTestMonitor(t, r, nil)
	m.opThreshold = 1
	for i := 1; i <= heartbeatFailureLimit; i++ {
		r.cEnc.EncryptBlock(make([]byte, 16), 0, nil)
		m.tick()
		assertServing(t, m, code, i == heartbeatFailureLimit)
	}
}

// An op count that cannot be persisted is struck like a failed rotation, and the unflushed count is
// credited once a flush succeeds.
func TestFlushOpCountsPersistFailureSuspends(t *testing.T) {
	r := newTestRotator(t, "")
	m, code := newTestMonitor(t, r, nil)
	m.opThreshold = 1 << 20
	r.cEnc.EncryptBlock(make([]byte, 16), 0, nil)
	dir := filepath.Dir(r.configPath)
	if err := os.Chmod(dir, 0500); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0700) })
	for i := 1; i <= heartbeatFailureLimit; i++ {
		m.tick()
		assertServing(t, m, code, i == heartbeatFailureLimit)
	}
	os.Chmod(dir, 0700)
	m.tick()
	assertServing(t, m, code, false)
	if got := loadRing(t, r).Keys[0].OpCount; got != 1 {
		t.Errorf("persisted op count = %d, want 1", got)
	}
}

// A refusal during a demanded rotation suspends at once.
func TestRotationRefusalSuspends(t *testing.T) {
	m, code := newTestMonitor(t, newTestRotator(t, ""), nil)
	m.rotationFailed("rekey", fmt.Errorf("gateway: %w", tkc.ErrDenied))
	assertServing(t, m, code, true)
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
	m, code := newTestMonitor(t, r, hb)
	m.opThreshold = 1
	for i := 1; i < heartbeatFailureLimit; i++ {
		r.cEnc.EncryptBlock(make([]byte, 16), 0, nil)
		m.tick()
		assertServing(t, m, code, false)
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
	m, code := newTestMonitor(t, r, hb)
	m.tick()
	m.tick()
	hb.answer = model.TKFSHeartbeatResponse{}
	m.tick()
	if m.rotateFailures != 0 {
		t.Fatalf("rotateFailures = %d after a quiet tick, want 0", m.rotateFailures)
	}
	hb.answer = model.TKFSHeartbeatResponse{Command: model.TKFSCommandRekey}
	m.tick()
	assertServing(t, m, code, false)
	restore()
}

// A rekey the pre-mount heartbeat brings back is carried out before anything is served, so failing it
// ends the mount even when it is an outage, and reports the unmount the key service would otherwise miss.
func TestVerifyKeyServiceRekeyFailureIsFatal(t *testing.T) {
	r := newTestRotator(t, "")
	failGenerate(r)
	hb := &fakeHeartbeater{answer: model.TKFSHeartbeatResponse{Command: model.TKFSCommandRekey}}
	m, code := newTestMonitor(t, r, hb)
	m.verifyKeyService()
	if *code != exitcodes.RotateFailed {
		t.Errorf("exit code = %d, want %d", *code, exitcodes.RotateFailed)
	}
	if got := hb.events[len(hb.events)-1]; got != model.TKFSEventUnmount {
		t.Errorf("last event = %q, want the unmount", got)
	}
}

// Before mounting, failures that were the key service rejecting this instance's credentials exit as
// revoked, which a systemd unit does not restart; any other outage exits 36, which it does.
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
	m, code := newTestMonitor(t, newTestRotator(t, ""), hb)
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
	m, code := newTestMonitor(t, r, hb)
	for i := 1; i <= heartbeatFailureLimit; i++ {
		hb.err = nil
		m.tick() // heartbeat answers, rotation fails
		if i == heartbeatFailureLimit {
			break
		}
		hb.err = errors.New("connection refused")
		m.tick() // heartbeat fails: must not clear the rotation strikes
	}
	assertServing(t, m, code, true)
}

// Before mounting, a key already past its op budget must not start serving, so a failed rotation ends
// the mount even as an outage.
func TestFlushOpCountsBeforeMountRotationFailureIsFatal(t *testing.T) {
	r := newTestRotator(t, "")
	failGenerate(r)
	m, code := newTestMonitor(t, r, nil)
	m.opThreshold = 1
	r.cEnc.EncryptBlock(make([]byte, 16), 0, nil)
	m.flushOpCountsBeforeMount()
	if *code != exitcodes.RotateFailed {
		t.Errorf("exit code = %d, want %d", *code, exitcodes.RotateFailed)
	}
}

// The pre-mount heartbeat reports the mount and later beats report nothing, and ending the mount reports the
// unmount once, whichever teardown paths reach it.
func TestHeartbeatReportsMountAndUnmount(t *testing.T) {
	r := newTestRotator(t, "")
	hb := &fakeHeartbeater{}
	m, _ := newTestMonitor(t, r, hb)
	m.verifyKeyService()
	m.tick()
	m.reportUnmount()
	m.reportUnmount()
	want := []model.TKFSHeartbeatEvent{model.TKFSEventMount, model.TKFSEventNone, model.TKFSEventUnmount}
	if !slices.Equal(hb.events, want) {
		t.Errorf("events = %v, want %v", hb.events, want)
	}
}

// A mount the key service never heard of has no unmount to report, and a refusal that suspends one
// reports none.
func TestUnmountIsReportedOnlyAfterAMount(t *testing.T) {
	r := newTestRotator(t, "")
	hb := &fakeHeartbeater{}
	m, _ := newTestMonitor(t, r, hb)
	m.reportUnmount()
	if len(hb.events) != 0 {
		t.Errorf("events = %v, want none before a mount was reported", hb.events)
	}

	hb = &fakeHeartbeater{}
	m, code := newTestMonitor(t, r, hb)
	m.verifyKeyService()
	hb.err = fmt.Errorf("gateway: %w", tkc.ErrDenied)
	m.tick()
	assertServing(t, m, code, true)
	if got := hb.events[len(hb.events)-1]; got == model.TKFSEventUnmount {
		t.Errorf("a suspended mount reported an unmount")
	}
}

// An unmount report that gets no answer is given up after its budget rather than holding the exit.
func TestUnmountReportIsBounded(t *testing.T) {
	r := newTestRotator(t, "")
	hb := &fakeHeartbeater{}
	m, _ := newTestMonitor(t, r, hb)
	m.verifyKeyService()
	hb.block = make(chan struct{})
	defer close(hb.block)
	defer func(d time.Duration) { unmountReportBudget = d }(unmountReportBudget)
	unmountReportBudget = 50 * time.Millisecond

	start := time.Now()
	m.reportUnmount()
	if waited := time.Since(start); waited > time.Second {
		t.Errorf("reportUnmount waited %v", waited)
	}
}
