package tkc

import (
	"encoding/json"
	"os"
	"sync"

	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

var (
	c        KMSConnector
	initOnce sync.Once
)

// Connect starts up our connection to the KMS.  Should be the first thing we do.
func Connect(cfg *TKConfig) {
	initOnce.Do(func() {
		dta, _ := json.Marshal(cfg)
		tlog.Info.Printf("Connecting to KMS: %s", string(dta))
		c = NewTKConnector(cfg)
		tlog.Info.Printf("Successfully connected to KMS")
	})
}

// Get retrieves the connection to the KMS
func Get() KMSConnector {
	if nil == c {
		tlog.Fatal.Printf("Attempted to retrieve KMS connection before initialization")
		os.Exit(exitcodes.Other)
	}
	return c
}
