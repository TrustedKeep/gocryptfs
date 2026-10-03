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
// Only mount(-like) processes call Connect. The id (NodeID) comes from the config. The instance
// identity does not: it lives in the key ring, which is not loaded yet, so the caller hands it over
// with DataKey().AdoptIdentity once it has one.
//
// mockAWS makes the gateway connector prove tkutils' mock AWS machine instead of reading EC2 IMDS, and
// sharedStorage makes it report -sharedstorage, which a gateway requiring binding refuses. Binding is the
// gateway's, so the search connector takes neither.
func Connect(gatewayHost, gatewayCertDir, id string, mockKMS, mockAWS, isSearch, sharedStorage bool) {
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
			dkc = newGatewayConnector(gatewayHost, gatewayCertDir, id, mockAWS, sharedStorage)
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
