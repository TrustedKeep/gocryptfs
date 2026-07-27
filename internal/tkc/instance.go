package tkc

import (
	"os"
	"sync"

	"github.com/TrustedKeep/tkutils/v2/kem"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

var (
	c        KMSConnector
	gw       GatewayConnector
	initOnce sync.Once
)

const (
	EnvelopeIDLength   = 36 //UUID length, including the hyphens
	EnvelopeIDAttrName = "user.envID"
	WrappedKeyAttrName = "user.wrapped"

	NameTransformEnvName = "eme_fn_key"
)

// KMSConnector connects the encryptor to a KMS (envelope key model). It is retained for
// the existing crypto/key model; the gateway KEK model (GatewayConnector) supersedes it
// and is wired into the crypto path in a later phase.
type KMSConnector interface {
	GetKey(path []byte) (key []byte, err error)
	GetEnvelopeKey(id string) (key kem.Kem, err error)
	CreateEnvelopeKey(ktStr string, name string) (id string, key kem.Kem, err error)
	GetCurrentKeyID() string
	SetCurrentKeyID(string)
}

// Connect starts up our key-provider connections. Should be the first thing we do.
//
// In gateway mode — the default now that TrustedBoundary is gone — we establish the mTLS
// GatewayConnector to TrustedGateway. The mock and search providers keep serving the
// envelope KMSConnector so the existing crypto path stays functional; wiring the gateway
// KEK into that path is a later phase.
//
// mockAWS selects the source of the signed instance identity document the gateway connector
// will attach to data-key requests (mock session vs real AWS IMDS); it is threaded to the
// connector now, the document itself is attached in a later phase.
func Connect(gatewayHost, gatewayCertDir, id string, mockKMS, mockAWS, isSearch bool) {
	initOnce.Do(func() {
		switch {
		case isSearch:
			tlog.Info.Printf("Opening TrustedSearch key provider")
			c = newSearchConnector()
		case mockKMS:
			tlog.Info.Printf("Opening mock KMS local store")
			c = newMockConnector(id)
		default:
			tlog.Info.Printf("Connecting to TrustedGateway: %s", gatewayHost)
			gw = newGatewayConnector(gatewayHost, gatewayCertDir, id, mockAWS)
		}
	})
}

// Get retrieves the envelope-model KMS connector.
func Get() KMSConnector {
	if nil == c {
		tlog.Fatal.Printf("Attempted to retrieve KMS connection before initialization")
		os.Exit(exitcodes.Other)
	}
	return c
}

// Gateway retrieves the gateway KEK connector.
func Gateway() GatewayConnector {
	if nil == gw {
		tlog.Fatal.Printf("Attempted to retrieve gateway connection before initialization")
		os.Exit(exitcodes.Other)
	}
	return gw
}
