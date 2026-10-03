package main

import (
	"errors"
	"fmt"
	"sync/atomic"
	"time"

	"github.com/TrustedKeep/tkutils/v2/model"

	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/tkc"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// heartbeatInterval is how often the mount reports itself to the key service, and how often it flushes
// the key op counter. With heartbeatFailureLimit it also sets the window a revoked instance can
// keep serving for: fifteen minutes.
const heartbeatInterval = 5 * time.Minute

// heartbeatFailureLimit is how many consecutive failures end the mount. A definitive rejection
// does not wait the count out.
const heartbeatFailureLimit = 3

// forcefulUnmountGrace is how long a shutdown gives a busy mountpoint to free up before it stops
// trying for a clean unmount. A stale mountpoint is an operator cleanup problem; a filesystem still
// serving after the key service can no longer vouch for it is a security failure.
const forcefulUnmountGrace = 10 * time.Second

// defaultRotateOpThreshold is how many encrypt operations one data key covers before the mount
// rotates to a fresh one — about 4.4 TB at the default block size. A quarter of NIST's 2^32 bound
// for random nonces, which is conservative here because these nonces are counter-derived.
const defaultRotateOpThreshold = 1 << 30

// resolveRotateOpThreshold maps a -rotate-op-threshold value onto the threshold to use. Zero is
// unset and means the default; there is no value that turns auto-rotation off.
func resolveRotateOpThreshold(v int64) uint64 {
	if v <= 0 {
		return defaultRotateOpThreshold
	}
	return uint64(v)
}

// autoRotateThreshold resolves -rotate-op-threshold for this mount. A read-only mount performs no
// encrypt operations, so what turning the counter off there actually suppresses is rotating on a
// count inherited from disk, which would write the cipherdir behind a flag that refuses to.
func autoRotateThreshold(args *argContainer) uint64 {
	if args.ro {
		return 0
	}
	return resolveRotateOpThreshold(args.rotateOpThreshold)
}

// keyServiceMonitor is the mount's periodic key-service work: the heartbeat that keeps its
// authorization current, reports its key-ring index and collects any rekey asked of it, and the
// op-counter flush that drives auto-rotation. They share one timer and neither needs its own goroutine.
type keyServiceMonitor struct {
	// hb is nil unless the connector has a heartbeat route to beat to. That is what keeps
	// heartbeat-death away from -mock-kms and every integration mount: a filesystem that
	// unmounts itself over a heartbeat it could never send would take the test suite with it.
	hb      tkc.Heartbeater
	rotator *keyRotator
	// readOnly suppresses the rekey a heartbeat can bring back, for the reason -ro suppresses
	// auto-rotation: rotating writes the key ring, and this mount may not write the cipherdir.
	readOnly bool
	// opThreshold is the operation count that triggers auto-rotation. Zero disables it.
	opThreshold uint64
	// srv is nil until the filesystem is mounted.
	srv        interface{ Unmount() error }
	mountpoint string
	exit       func(code int)

	failures int
}

// verifyKeyService sends the first heartbeat, before anything is mounted. The heartbeat is what bounds
// how long a revoked instance keeps serving, so a key service that will not answer it — refused,
// unreachable, or too old to have the route — must not get a mountpoint in the first place.
func (m *keyServiceMonitor) verifyKeyService() {
	if m.hb == nil {
		return
	}
	resp, err := m.hb.Heartbeat(m.rotator.writeKey())
	switch {
	case errors.Is(err, tkc.ErrNotImplemented):
		tlog.Fatal.Printf("The key service does not implement the heartbeat route, so this mount would run with " +
			"no revocation: blocking or de-authorizing it could not unmount it. Upgrade the key service.")
	case errors.Is(err, tkc.ErrSharedStorageRefused):
		tlog.Fatal.Printf("%v", err)
	case errors.Is(err, tkc.ErrDenied):
		tlog.Fatal.Printf("The key service refused this instance: %v", err)
	case err != nil:
		tlog.Fatal.Printf("The first heartbeat did not reach the key service: %v", err)
	case resp.Command == model.TKFSCommandRekey:
		// A short mount never reaches the first scheduled beat.
		m.rekey()
	}
	if err != nil {
		m.exit(keyServiceExit(err, exitcodes.Revoked))
	}
}

// startKeyServiceMonitor runs the monitor in the background, once the filesystem is serving.
func startKeyServiceMonitor(m *keyServiceMonitor) {
	if m.hb == nil && m.opThreshold == 0 {
		return
	}
	go m.run()
}

func (m *keyServiceMonitor) run() {
	for {
		time.Sleep(heartbeatInterval)
		if m.hb != nil {
			m.beat()
		}
		m.flushOpCounts()
	}
}

// beat sends one heartbeat and acts on the answer, including any rekey it brings back.
func (m *keyServiceMonitor) beat() {
	resp, err := m.hb.Heartbeat(m.rotator.writeKey())
	if die, reason := m.classify(err); die {
		m.shutdownNow("Heartbeat: "+reason, keyServiceExit(err, exitcodes.Revoked))
		return
	}
	switch resp.Command {
	case model.TKFSCommandRekey:
		m.rekey()
	case model.TKFSCommandNone:
	default:
		// An unrecognized command means carry on. The unambiguous "stop" is the 403, not a
		// string this build has to understand.
		tlog.Info.Printf("Heartbeat: ignoring unrecognized command %q from the key service", resp.Command)
	}
}

// rekey carries out a rotation the key service asked for and reports the new index at once, so what an
// operator watches moves within seconds rather than at the next tick.
func (m *keyServiceMonitor) rekey() {
	if m.readOnly {
		// The directive stays pending, for a writable mount of this instance to collect.
		tlog.Info.Printf("Heartbeat: rekey requested, but a read-only mount cannot rotate")
		return
	}
	idx, err := m.rotator.rotate()
	if err != nil {
		// Same rule as the counter-driven rotation: it succeeds or the mount ends. A filesystem
		// told its key should change must not go on writing under the old one.
		m.shutdownNow(fmt.Sprintf("Heartbeat: the key service asked for a rekey and it failed: %v", err),
			keyServiceExit(err, exitcodes.RotateFailed))
		return
	}
	tlog.Info.Printf("Heartbeat: rekey requested; rotated to key-ring index %d", idx)
	// A report, not a liveness check: an outage here spends none of the three-strike budget, but a
	// refusal still ends the mount.
	_, err = m.hb.Heartbeat(m.rotator.writeKey())
	switch {
	case errors.Is(err, tkc.ErrDenied), errors.Is(err, tkc.ErrNotImplemented):
		_, reason := m.classify(err)
		m.shutdownNow("Heartbeat: "+reason, keyServiceExit(err, exitcodes.Revoked))
	case err != nil:
		tlog.Info.Printf("Heartbeat: reporting key-ring index %d failed: %v.", idx, err)
	}
}

// classify reports whether one heartbeat outcome ends the mount, advancing the failure counter as it
// goes. A decision about this instance ends it at once; failing to reach the key service is an outage,
// survivable twice.
func (m *keyServiceMonitor) classify(err error) (die bool, reason string) {
	switch {
	case errors.Is(err, tkc.ErrSharedStorageRefused):
		return true, "a gateway that requires instance binding refused this -sharedstorage mount"
	case errors.Is(err, tkc.ErrDenied):
		return true, "the key service withdrew this instance's authorization"
	case errors.Is(err, tkc.ErrNotImplemented):
		return true, "the key service does not implement the heartbeat route"
	case err != nil:
		m.failures++
		tlog.Info.Printf("Heartbeat failed (%d of %d): %v", m.failures, heartbeatFailureLimit, err)
		if m.failures >= heartbeatFailureLimit {
			return true, fmt.Sprintf("lost contact with the key service (%d consecutive failures)", m.failures)
		}
		return false, ""
	}
	m.failures = 0
	return false, ""
}

// fatalExitCode records that a monitor is ending this mount, and with what code. Without it the
// code would be a race: a clean unmount lets srv.Wait() return in doMount and the process exit 0
// before shutdownNow reaches its own os.Exit. doMount defers a check of this, registered first so
// it runs last.
var fatalExitCode atomic.Int32

// shutdownNow ends the mount and is not abortable. A clean unmount is attempted first; if the
// mountpoint stays busy it gives up and exits, leaving a mountpoint whose every operation fails.
func (m *keyServiceMonitor) shutdownNow(reason string, code int) {
	fatalExitCode.Store(int32(code))
	if m.srv == nil {
		tlog.Fatal.Printf("%s.", reason)
		m.exit(code)
		return
	}
	tlog.Fatal.Printf("%s. Unmounting %s.", reason, m.mountpoint)
	if err := m.srv.Unmount(); err != nil {
		tlog.Fatal.Printf("Unmount failed: %v. Retrying once in %v, then leaving the mountpoint dead.", err, forcefulUnmountGrace)
		time.Sleep(forcefulUnmountGrace)
		if err := m.srv.Unmount(); err != nil {
			tlog.Fatal.Printf("Unmount still failing: %v.", err)
		}
	}
	m.exit(code)
}

// flushOpCounts persists this mount's encrypt-op counter into the key ring and rotates when the
// active key has crossed the threshold. Either step failing ends the mount: continuing would go on
// drawing nonces under a key whose budget nothing can account for any more, and the usual cause —
// an unreachable key service — is one the heartbeat would end the mount over regardless.
func (m *keyServiceMonitor) flushOpCounts() {
	if m.rotator == nil || m.opThreshold == 0 {
		return
	}
	due, err := m.rotator.flushOpCounts(m.opThreshold)
	if err != nil {
		m.shutdownNow(fmt.Sprintf("Cannot persist this mount's key operation count: %v", err), exitcodes.RotateFailed)
		return
	}
	if !due {
		return
	}
	idx, err := m.rotator.rotate()
	if err != nil {
		m.shutdownNow(fmt.Sprintf("The active key passed %d operations but rotating away from it failed: %v",
			m.opThreshold, err), keyServiceExit(err, exitcodes.RotateFailed))
		return
	}
	tlog.Info.Printf("Auto-rotated to key-ring index %d: the previous key passed %d operations", idx, m.opThreshold)
}

// flushOpCountsAtUnmount persists the counter one last time on the way out, so a mount that lived
// less than one interval still contributes the budget its writes spent.
//
// It must run before any Wipe(), which publishes a fresh zeroed counter that would make the delta
// underflow.
func (m *keyServiceMonitor) flushOpCountsAtUnmount() {
	if m.rotator == nil || m.opThreshold == 0 {
		return
	}
	if _, err := m.rotator.flushOpCounts(m.opThreshold); err != nil {
		tlog.Info.Printf("Could not persist the key operation count at unmount: %v", err)
	}
}
