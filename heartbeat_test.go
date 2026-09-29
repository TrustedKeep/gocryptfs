package main

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/TrustedKeep/tkutils/v2/model"
	"github.com/rfjakob/gocryptfs/v2/internal/tkc"
)

// A refusal is a decision about this instance and ends it at
// once; an outage is survivable twice. Either way it ends the same way, busy mountpoint or not.
func TestHeartbeatClassify(t *testing.T) {
	ok := model.TKFSHeartbeatResponse{}
	transport := errors.New("connection refused")
	denied := fmt.Errorf("gateway: %w", tkc.ErrDenied)

	t.Run("403 dies without waiting the count out", func(t *testing.T) {
		m := &keyServiceMonitor{}
		if die, _ := m.classify(ok, denied); !die {
			t.Error("a 403 must end the mount")
		}
	})

	t.Run("shutdown directive dies", func(t *testing.T) {
		m := &keyServiceMonitor{}
		die, reason := m.classify(model.TKFSHeartbeatResponse{Command: model.TKFSCommandShutdown}, nil)
		if !die {
			t.Error("a shutdown directive must end the mount")
		}
		if reason == "" {
			t.Error("a shutdown should carry a reason to log")
		}
	})

	t.Run("third consecutive failure dies, not before", func(t *testing.T) {
		m := &keyServiceMonitor{}
		for i := 1; i < heartbeatFailureLimit; i++ {
			if die, _ := m.classify(ok, transport); die {
				t.Fatalf("failure %d must not end the mount", i)
			}
		}
		die, reason := m.classify(ok, transport)
		if !die {
			t.Errorf("failure %d must end the mount", heartbeatFailureLimit)
		}
		if !strings.Contains(reason, fmt.Sprintf("%d consecutive", heartbeatFailureLimit)) {
			t.Errorf("reason = %q, want the failure count", reason)
		}
	})

	t.Run("a success resets the counter", func(t *testing.T) {
		m := &keyServiceMonitor{}
		m.classify(ok, transport)
		m.classify(ok, transport)
		m.classify(ok, nil)
		if die, _ := m.classify(ok, transport); die {
			t.Error("the counter should have restarted")
		}
	})
}

// A gateway that cannot answer a heartbeat cannot revoke this instance either. verifyKeyService keeps
// such a mount from starting; if one is downgraded underneath a running mount, the beat that finds
// out ends it rather than serving on with revocation quietly off.
func TestHeartbeatMissingRouteKills(t *testing.T) {
	m := &keyServiceMonitor{}
	die, reason := m.classify(model.TKFSHeartbeatResponse{}, fmt.Errorf("gateway: %w", tkc.ErrNotImplemented))
	if !die {
		t.Error("a missing route must end the mount")
	}
	if reason == "" {
		t.Error("a missing route should carry a reason to log")
	}
}

// A rekey is work to do, not a reason to stop. classify must leave the mount serving so beat() can
// rotate; only the shutdown directive and a refusal end it.
func TestHeartbeatRekeyDoesNotKill(t *testing.T) {
	m := &keyServiceMonitor{}
	resp := model.TKFSHeartbeatResponse{Command: model.TKFSCommandRekey}
	if die, _ := m.classify(resp, nil); die {
		t.Error("a rekey must not end the mount")
	}
}

// -ro suppresses a rekey for the same reason it suppresses the counter: rotating writes the key ring,
// and a read-only mount may not write the cipherdir. The directive stays pending for a writable mount.
// With no rotator and no server wired, anything but an early return here nil-derefs.
func TestHeartbeatReadOnlyMountDoesNotRotate(t *testing.T) {
	m := &keyServiceMonitor{readOnly: true}
	m.rekey()
}

// A command this build does not know means carry on: the unambiguous "stop" is the 403, not a string
// an older instance would have to understand.
func TestHeartbeatUnknownCommandDoesNotKill(t *testing.T) {
	m := &keyServiceMonitor{}
	if die, _ := m.classify(model.TKFSHeartbeatResponse{Command: "reticulate-splines"}, nil); die {
		t.Error("an unrecognized command must not end the mount")
	}
}

// The index is read off the write key, so it moves with a rotation without the monitor tracking it.
// A monitor with no rotator is a test construction, not a mount; it must not panic the beat goroutine.
func TestHeartbeatKeyIdxWithoutARotator(t *testing.T) {
	if got := (&keyServiceMonitor{}).keyIdx(); got != 0 {
		t.Errorf("keyIdx = %d, want 0", got)
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
