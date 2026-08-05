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

// Connect establishes the KEK data-key connector. It is the first key-provider call and runs
// exactly once. The connector depends on the mode:
//   - search:  the TrustedSearch KMS over mTLS + tenant token (ramdisk-provisioned certs)
//   - mockKMS: an in-process bbolt-backed mock gateway (no live key service required)
//   - default: TrustedGateway over mTLS (operator-provisioned certs)
//
// Only mount(-like) processes call Connect (-init writes the config without contacting the
// key service); the id (NodeID) is read back from the config on every mount, so the first
// mount's generate and all later unwraps share one keyspace. mockAWS selects the
// instance-identity source for the real gateway connector (mock vs AWS IMDS); it is threaded
// now and attached to requests in a later phase.
func Connect(gatewayHost, gatewayCertDir, id string, mockKMS, mockAWS, isSearch bool) {
	initOnce.Do(func() {
		switch {
		case isSearch:
			tlog.Info.Printf("Opening TrustedSearch key provider")
			dkc = newSearchConnector(id)
		case mockKMS:
			tlog.Info.Printf("Opening mock gateway local store")
			dkc = newMockGatewayConnector(id, "")
		default:
			tlog.Info.Printf("Connecting to TrustedGateway: %s", gatewayHost)
			dkc = newGatewayConnector(gatewayHost, gatewayCertDir, id, mockAWS)
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
