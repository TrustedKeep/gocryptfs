package main

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"strings"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// info pretty-prints the contents of the config file at "filename" for human
// consumption, stripping out sensitive data.
// This is called when you pass the "-info" option.
func info(filename string) {
	// Read from disk
	js, err := ioutil.ReadFile(filename)
	if err != nil {
		tlog.Fatal.Printf("Reading config file failed: %v", err)
		os.Exit(exitcodes.LoadConf)
	}
	// Unmarshal
	var cf configfile.ConfFile
	err = json.Unmarshal(js, &cf)
	if err != nil {
		tlog.Fatal.Printf("Failed to unmarshal config file")
		os.Exit(exitcodes.LoadConf)
	}
	if cf.Version != contentenc.CurrentVersion {
		tlog.Fatal.Printf("Unsupported on-disk format %d", cf.Version)
		os.Exit(exitcodes.LoadConf)
	}
	// Pretty-print
	fmt.Printf("FeatureFlags: %s\n", strings.Join(cf.FeatureFlags, " "))
}
