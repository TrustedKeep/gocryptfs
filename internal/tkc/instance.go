package tkc

import (
	"os"
	"sync"

	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

var (
	dkc      DataKeyConnector
	initOnce sync.Once
)

// ConnectOptions configures Connect. MockAWS and SharedStorage concern binding, which is the gateway's,
// so the search connector takes neither.
type ConnectOptions struct {
	GatewayHost    string
	GatewayCertDir string
	// NodeID identifies this mount on every call, and MountID this process on its heartbeat.
	NodeID  string
	MountID string
	// MockStoreID names the mock's key store: the config's NodeID, so mock mounts share a store only when
	// they share a config NodeID.
	MockStoreID   string
	MockKMS       bool
	MockAWS       bool
	Search        bool
	SharedStorage bool
}

// Connect establishes the KEK data-key connector, once: TrustedSearch's KMS with -search, an in-process
// mock with -mock-kms, and TrustedGateway otherwise. The instance identity lives in the key ring, which
// is not loaded yet, so the caller hands it over with DataKey().AdoptIdentity.
func Connect(o ConnectOptions) {
	initOnce.Do(func() {
		switch {
		case o.Search:
			tlog.Info.Printf("Opening TrustedSearch key provider")
			s := newSearchConnector(o.NodeID)
			s.mountID = o.MountID
			dkc = s
		case o.MockKMS:
			tlog.Info.Printf("Opening mock gateway local store")
			dkc = newMockGatewayConnector(o.MockStoreID, "")
		default:
			tlog.Info.Printf("Connecting to TrustedGateway: %s", o.GatewayHost)
			g := newGatewayConnector(o.GatewayHost, o.GatewayCertDir, o.NodeID, o.MockAWS, o.SharedStorage)
			g.mountID = o.MountID
			dkc = g
		}
	})
}

// DataKey retrieves the KEK data-key connector established by Connect.
func DataKey() DataKeyConnector {
	if dkc == nil {
		tlog.Fatal.Printf("Attempted to retrieve data-key connector before initialization")
		os.Exit(exitcodes.Other)
	}
	return dkc
}
