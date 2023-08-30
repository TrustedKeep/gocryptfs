package main

import (
	"fmt"
	"os"
	"strings"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
)

// info pretty-prints the contents of the config file at "filename" for human
// consumption, stripping out sensitive data.
// This is called when you pass the "-info" option.
func info(filename string) {
	cf, err := configfile.Load(filename)
	if err != nil {
		fmt.Printf("Loading config file failed: %v\n", err)
		os.Exit(exitcodes.LoadConf)
	}
	// Pretty-print
	fmt.Printf("FeatureFlags:      %s\n", strings.Join(cf.FeatureFlags, " "))

}
