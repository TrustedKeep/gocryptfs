// Tests run for (almost all) combinations of plaintextnames.
//
// File reading, writing, modification, truncate, ...
//
// Runs all tests N times, for the combinations of different flags specified
// in the `matrix` variable.

package matrix

import (
	"flag"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// Several tests need to be aware if plaintextnames is active or not, so make this
// a global variable
var testcase testcaseMatrix

var ctlsockPath string

type testcaseMatrix struct {
	plaintextnames bool
	extraArgs      []string
}

// isSet finds out if `extraArg` is set in `tc.extraArgs`
func (tc *testcaseMatrix) isSet(extraArg string) bool {
	for _, v := range tc.extraArgs {
		if v == extraArg {
			return true
		}
	}
	return false
}

// This is the entry point for the tests
func TestMain(m *testing.M) {
	// No Raw64 axis. The -raw64 flag exists (upstream parity) but cannot change what lands on
	// disk: Create sets FlagRaw64 on every filesystem it writes, and the mount takes the encoding
	// from the config, overriding the command line. Upstream's raw64=false cases only differed
	// here because -zerokey meant there was no config to override them, so a case for it now would
	// be an exact duplicate of "Normal" that looks like coverage.
	var matrix = []testcaseMatrix{
		// Normal
		{false, nil},
		// Plaintextnames
		{true, nil},
		// -sharedstorage
		{false, []string{"-sharedstorage"}},
		// -deterministic-names
		{false, []string{"-deterministic-names"}},
		// Test xchacha
		{false, []string{"-xchacha"}},
	}

	// Make "testing.Verbose()" return the correct value
	flag.Parse()
	var i int
	for i, testcase = range matrix {
		if testing.Verbose() {
			fmt.Printf("matrix: testcase = %#v\n", testcase)
		}
		ctlsockPath = fmt.Sprintf("%s/ctlsock.%d", test_helpers.TmpDir, i)
		// -init writes the config and, unless names are plaintext or deterministic, the diriv.
		// The name and content-cipher options are recorded in the config, so they have to be
		// chosen here: passing them at mount time would be silently overridden by the config.
		// -sharedstorage is a genuine mount option and stays below.
		test_helpers.ResetTmpDir(false)
		initOpts := []string{
			fmt.Sprintf("-plaintextnames=%v", testcase.plaintextnames),
		}
		for _, a := range testcase.extraArgs {
			if a == "-deterministic-names" || a == "-xchacha" {
				initOpts = append(initOpts, a)
			}
		}
		test_helpers.InitDefaultCipherDir(initOpts...)
		opts := []string{"-ctlsock", ctlsockPath}
		//opts = append(opts, "-fusedebug")
		if testcase.isSet("-sharedstorage") {
			opts = append(opts, "-sharedstorage")
		}
		test_helpers.MountOrExit(test_helpers.DefaultCipherDir, test_helpers.DefaultPlainDir, opts...)
		before := test_helpers.ListFds(0, test_helpers.TmpDir)
		t0 := time.Now()
		r := m.Run()
		if testing.Verbose() {
			fmt.Printf("matrix[%d]: run took %v\n", i, time.Since(t0))
		}
		// Catch fd leaks in the tests. NOTE: this does NOT catch leaks in
		// the gocryptfs FUSE process, but only in the tests that access it!
		// All fds that point outside TmpDir are not interesting (the Go test
		// infrastucture creates temporary log files we don't care about).
		after := test_helpers.ListFds(0, test_helpers.TmpDir)
		if len(before) != len(after) {
			fmt.Printf("fd leak in test process? before, after:\n%v\n%v\n", before, after)
			os.Exit(1)
		}
		test_helpers.UnmountPanic(test_helpers.DefaultPlainDir)
		if r != 0 {
			fmt.Printf("TestMain: matrix[%d] = %#v failed\n", i, testcase)
			os.Exit(r)
		}
		// The ctlsock file is deleted asynchronously after unmount.
		// Ensure it is delete here so it does not race (and trip up) ResetTmpDir() of the next
		// loop iteration.
		os.Remove(ctlsockPath)
	}
	os.Exit(0)
}
