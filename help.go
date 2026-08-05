package main

import (
	"fmt"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

const tUsage = "" +
	"Usage: " + tlog.ProgramName + " -init|-passwd|-info [OPTIONS] CIPHERDIR\n" +
	"  or   " + tlog.ProgramName + " [OPTIONS] CIPHERDIR MOUNTPOINT\n"

// helpShort is what gets displayed when passed "-h" or on syntax error.
func helpShort() {
	printVersion()
	fmt.Print("\n")
	fmt.Print(tUsage)
	fmt.Printf(`
Common Options (use -hh to show all):
  -allow_other       Allow other users to access the mount
  -fg                Stay in the foreground
  -fusedebug         Debug FUSE calls
  -h, -help          This short help text
  -init              Initialize encrypted directory
  -gateway-host      Host:port of the TrustedGateway
  -gateway-cert-dir  Directory with the gateway mTLS material: tls.crt, tls.key, ca.crt
  -node-id           Unique identifier for the mount
  -mock-aws          Use a mock AWS connection for development and testing
  -mock-kms          Use a mock gateway (bbolt-backed) for development and testing
  -search            Use TrustedSearch as a key provider
  -version           Print version information
  --                 Stop option parsing
`)
}

// helpLong gets only displayed on "-hh"
func helpLong() {
	printVersion()
	fmt.Print("\n")
	fmt.Print(tUsage)
	fmt.Printf(`
Notes: All options can equivalently use "-" (single dash) or "--" (double dash).
       A standalone "--" stops option parsing.
`)
	fmt.Printf("\nOptions:\n")
	flagSet.PrintDefaults()
}
