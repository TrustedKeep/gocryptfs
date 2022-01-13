package tkc

import (
	"os"
	"sync"

	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

var (
	c        KMSConnector
	initOnce sync.Once
)

// KMSConnector connects the encryptor to a KMS
type KMSConnector interface {
	GetKey(path []byte) (key []byte, err error)
}

// Connect starts up our connection to the KMS.  Should be the first thing we do.
func Connect(tbHost, id string, mockAWS, mockKMS bool) {
	initOnce.Do(func() {
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
