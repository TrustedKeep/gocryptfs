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
func Connect(cfg *TKConfig) {
	initOnce.Do(func() {
		tlog.Info.Printf("Connecting to TrustedBoundary: %s", cfg.BoundaryHost)
		c = NewTBConnector(cfg)
		tlog.Info.Printf("Successfully connected to TrustedBoundary")
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
