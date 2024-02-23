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
	initOnce sync.Once
)

const (
	EnvelopeIDLength   = 36 //UUID length, including the hyphens
	EnvelopeIDAttrName = "user.envID"
	WrappedKeyAttrName = "user.wrapped"

	NameTransformEnvName = "eme_fn_key"
)

// KMSConnector connects the encryptor to a KMS
type KMSConnector interface {
	GetKey(path []byte) (key []byte, err error)
	GetEnvelopeKey(id string) (key kem.Kem, err error)
	CreateEnvelopeKey(ktStr string, name string) (id string, key kem.Kem, err error)
	GetCurrentKeyID() string
	SetCurrentKeyID(string)
}

// Connect starts up our connection to the KMS.  Should be the first thing we do.
func Connect(tbHost, id string, mockAWS, mockKMS, isSearch bool, caPath string) {
	initOnce.Do(func() {
		if isSearch {
			tlog.Info.Printf("Opening TrustedSearch key provider")
			c = newSearchConnector(caPath)
			return
		}
		if mockKMS {
			tlog.Info.Printf("Opening mock KMS local store")
			c = newMockConnector(id)
			return
		}
		tlog.Info.Printf("Connecting to TrustedBoundary: %s", tbHost)
		c = newtbConnector(tbHost, id, mockAWS)
	})
}

// Get retrieves the connection to the KMS
func Get() KMSConnector {
	if nil == c {
		tlog.Fatal.Printf("Attempted to retrieve Boundary connection before initialization")
		os.Exit(exitcodes.Other)
	}
	return c
}
