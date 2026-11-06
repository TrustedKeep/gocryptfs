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
// does not wait the count out. Rotations a rekey or the op counter demand get the same budget.
const heartbeatFailureLimit = 3

// firstHeartbeatAttempts is how many times the pre-mount heartbeat is tried before the mount gives
// up. A key service that has just minted this instance's KEK may answer from a node that cannot see
// it yet, and a gateway can briefly fail a binding check it cannot make; neither is a refusal.
const firstHeartbeatAttempts = 4

// firstHeartbeatRetryDelay is the wait between pre-mount heartbeat attempts. A variable so tests do
// not sleep.
var firstHeartbeatRetryDelay = 5 * time.Second

// firstHeartbeatBudget bounds the pre-mount retries in time as well as in attempts: one attempt can
// take a request timeout per key-service host, and a mount that blows systemd's start timeout is
// killed instead of exiting with a code that says why. No retry starts after this much time.
var firstHeartbeatBudget = 45 * time.Second

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

	// failures counts heartbeats that failed in a row. rotateFailures counts ticks in a row in which
	// a demanded rotation (rekey or op counter) failed: one per tick however many failed in it, and
	// back to zero after a tick in which none did. rotationFailedThisTick tracks the current tick.
	failures               int
	rotateFailures         int
	rotationFailedThisTick bool
}

// outageExit is the exit code for a mount ending because the key service could not be reached. An
// outage is restartable, unless the failures were the key service rejecting this instance's
// credentials (a 401, or a TLS alert refusing its certificate), which a restart would only repeat.
func outageExit(err error) int {
	return keyServiceExit(err, exitcodes.KeyServiceUnreachable)
}

// verifyKeyService sends the first heartbeat, before anything is mounted. The heartbeat is what bounds
// how long a revoked instance keeps serving, so a key service that will not answer it — refused,
// unreachable, or too old to have the route — must not get a mountpoint in the first place. Anything
// but a refusal is retried a few times first, since it may be an outage that clears.
func (m *keyServiceMonitor) verifyKeyService() {
	if m.hb == nil {
		return
	}
	resp, err := m.firstHeartbeat()
	switch {
	case errors.Is(err, tkc.ErrNotImplemented):
		// Possibly a key service too old for the route, but a proxy or a deploy answers 404 too, so
		// this exits as an outage: a restart will mount once the route answers.
		tlog.Fatal.Printf("The key service does not answer the heartbeat route, so this mount would run with " +
			"no revocation: blocking or de-authorizing it could not unmount it. If the key service predates " +
			"the route, upgrade it.")
		m.exit(exitcodes.KeyServiceUnreachable)
	case errors.Is(err, tkc.ErrSharedStorageRefused):
		tlog.Fatal.Printf("%v", err)
		m.exit(exitcodes.SharedStorageRefused)
	case errors.Is(err, tkc.ErrDenied):
		tlog.Fatal.Printf("The key service refused this instance: %v", err)
		m.exit(exitcodes.Revoked)
	case err != nil:
		tlog.Fatal.Printf("The first heartbeat did not reach the key service: %v", err)
		m.exit(outageExit(err))
	case resp.Command == model.TKFSCommandRekey:
		// A short mount never reaches the first scheduled beat. Before mounting there is no old key in
		// use to keep serving under, so a rekey that fails ends the mount rather than being retried.
		if err := m.rekey(); err != nil {
			m.shutdownNow(fmt.Sprintf("The key service asked for a rekey before mounting and it failed: %v", err),
				keyServiceExit(err, exitcodes.RotateFailed))
		}
	}
}

// firstHeartbeat sends the pre-mount heartbeat, retrying anything but a refusal up to
// firstHeartbeatAttempts times.
func (m *keyServiceMonitor) firstHeartbeat() (model.TKFSHeartbeatResponse, error) {
	var resp model.TKFSHeartbeatResponse
	var err error
	start := time.Now()
	for attempt := 1; ; attempt++ {
		resp, err = m.hb.Heartbeat(m.rotator.writeKey())
		if err == nil || errors.Is(err, tkc.ErrDenied) || errors.Is(err, tkc.ErrSharedStorageRefused) ||
			errors.Is(err, tkc.ErrUnauthenticated) ||
			attempt == firstHeartbeatAttempts || time.Since(start)+firstHeartbeatRetryDelay > firstHeartbeatBudget {
			return resp, err
		}
		tlog.Info.Printf("The first heartbeat failed (attempt %d of %d), retrying in %v: %v",
			attempt, firstHeartbeatAttempts, firstHeartbeatRetryDelay, err)
		time.Sleep(firstHeartbeatRetryDelay)
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
		m.tick()
	}
}

// tick is one interval's work: the heartbeat, then the op-counter flush. A tick whose heartbeat
// answered and in which no demanded rotation failed clears the rotation failure count, which keeps
// "in a row" honest once a rotation stops being demanded, for example after a -ctlsock Rotate. A tick
// whose heartbeat failed clears nothing: it could not even learn whether a rekey is still pending.
func (m *keyServiceMonitor) tick() {
	m.rotationFailedThisTick = false
	heard := true
	if m.hb != nil {
		heard = m.beat()
	}
	if err := m.flushOpCounts(); err != nil {
		m.rotationFailed(m.opRotationFailure(), err)
	}
	if heard && !m.rotationFailedThisTick {
		m.rotateFailures = 0
	}
}

// beat sends one heartbeat and acts on the answer, including any rekey it brings back. It reports
// whether the key service answered.
func (m *keyServiceMonitor) beat() bool {
	resp, err := m.hb.Heartbeat(m.rotator.writeKey())
	if die, reason := m.classify(err); die {
		m.shutdownNow("Heartbeat: "+reason, outageExit(err))
		return false
	}
	if err != nil {
		return false
	}
	switch resp.Command {
	case model.TKFSCommandRekey:
		if err := m.rekey(); err != nil {
			m.rotationFailed("Heartbeat: the key service asked for a rekey and it failed", err)
		}
	case model.TKFSCommandNone:
	default:
		// An unrecognized command means carry on. The unambiguous "stop" is the 403, not a
		// string this build has to understand.
		tlog.Info.Printf("Heartbeat: ignoring unrecognized command %q from the key service", resp.Command)
	}
	return true
}

// rekey carries out a rotation the key service asked for and reports the new index at once, so what an
// operator watches moves within seconds rather than at the next tick. It returns the rotation's error
// for the caller to judge: retried at runtime, fatal before mounting.
func (m *keyServiceMonitor) rekey() error {
	if m.readOnly {
		// The directive stays pending, for a writable mount of this instance to collect.
		tlog.Info.Printf("Heartbeat: rekey requested, but a read-only mount cannot rotate")
		return nil
	}
	idx, err := m.rotator.rotate()
	if err != nil {
		return err
	}
	tlog.Info.Printf("Heartbeat: rekey requested; rotated to key-ring index %d", idx)
	// A report, not a liveness check: an outage here spends none of the three-strike budget, but a
	// refusal still ends the mount.
	_, err = m.hb.Heartbeat(m.rotator.writeKey())
	switch {
	case errors.Is(err, tkc.ErrDenied), errors.Is(err, tkc.ErrSharedStorageRefused):
		m.shutdownNow("Heartbeat: the key service refused this instance's report", keyServiceExit(err, exitcodes.Revoked))
	case err != nil:
		tlog.Info.Printf("Heartbeat: reporting key-ring index %d failed: %v.", idx, err)
	}
	return nil
}

// rotationFailed handles a rotation a rekey or the op counter demanded that did not happen. A refusal
// ends the mount at once. Anything else is retried: a rekey directive stays pending in keep, so the next
// heartbeat brings it back, and the op counter is still due at the next flush. Nothing is written
// before a rotation's generate succeeds, so a retry is safe. Only heartbeatFailureLimit failures in a
// row end the mount: a filesystem told its key should change must not write under the old one for long.
func (m *keyServiceMonitor) rotationFailed(what string, err error) {
	if errors.Is(err, tkc.ErrDenied) || errors.Is(err, tkc.ErrSharedStorageRefused) || errors.Is(err, errRotationFatal) {
		m.shutdownNow(fmt.Sprintf("%s: %v", what, err), keyServiceExit(err, exitcodes.RotateFailed))
		return
	}
	// One strike per tick: a rekey and the op counter failing in the same tick are one failure.
	if !m.rotationFailedThisTick {
		m.rotateFailures++
		m.rotationFailedThisTick = true
	}
	if m.rotateFailures >= heartbeatFailureLimit {
		m.shutdownNow(fmt.Sprintf("%s %d times in a row: %v", what, m.rotateFailures, err), exitcodes.RotateFailed)
		return
	}
	tlog.Info.Printf("%s (%d of %d), retrying at the next heartbeat: %v", what, m.rotateFailures, heartbeatFailureLimit, err)
}

// classify reports whether one heartbeat outcome ends the mount, advancing the failure counter as it
// goes. A decision about this instance ends it at once; failing to reach the key service is an outage,
// survivable twice. A missing route (404/501) is an outage here too: the pre-mount heartbeat already
// showed the key service has the route, so now it is a proxy, a load balancer, or one node mid-deploy.
func (m *keyServiceMonitor) classify(err error) (die bool, reason string) {
	switch {
	case errors.Is(err, tkc.ErrSharedStorageRefused):
		return true, "a gateway that requires instance binding refused this -sharedstorage mount"
	case errors.Is(err, tkc.ErrDenied):
		return true, "the key service withdrew this instance's authorization"
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
// active key has crossed the threshold. Failing to persist ends the mount: continuing would go on
// drawing nonces under a key whose budget nothing can account for any more. A failed rotation is
// returned for the caller to judge: retried at runtime for up to heartbeatFailureLimit intervals
// (rotationFailed), fatal before mounting (flushOpCountsBeforeMount).
func (m *keyServiceMonitor) flushOpCounts() error {
	if m.rotator == nil || m.opThreshold == 0 {
		return nil
	}
	due, err := m.rotator.flushOpCounts(m.opThreshold)
	if err != nil {
		m.shutdownNow(fmt.Sprintf("Cannot persist this mount's key operation count: %v", err), exitcodes.RotateFailed)
		return nil
	}
	if !due {
		return nil
	}
	idx, err := m.rotator.rotate()
	if err != nil {
		return err
	}
	tlog.Info.Printf("Auto-rotated to key-ring index %d: the previous key passed %d operations", idx, m.opThreshold)
	return nil
}

// opRotationFailure describes a failed op-threshold rotation.
func (m *keyServiceMonitor) opRotationFailure() string {
	return fmt.Sprintf("The active key passed %d operations but rotating away from it failed", m.opThreshold)
}

// flushOpCountsBeforeMount is flushOpCounts before anything is mounted. A key already past its budget
// must not start serving, so a rotation that fails here ends the mount rather than being retried.
func (m *keyServiceMonitor) flushOpCountsBeforeMount() {
	if err := m.flushOpCounts(); err != nil {
		m.shutdownNow(fmt.Sprintf("%s before mounting: %v", m.opRotationFailure(), err), keyServiceExit(err, exitcodes.RotateFailed))
	}
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
