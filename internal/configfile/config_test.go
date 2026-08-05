package configfile

import (
	"fmt"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
)

// TestLoadOldFormatRejected verifies the v3 format break: an old format-2 config (pre-KEK) is
// rejected fail-closed rather than silently mounted.
func TestLoadOldFormatRejected(t *testing.T) {
	_, err := Load("config_test/PlaintextNames.conf")
	if err == nil {
		t.Error("expected old format-2 config to be rejected, but Load succeeded")
	} else if testing.Verbose() {
		fmt.Println(err)
	}
}

func TestLoadV2StrangeFeature(t *testing.T) {
	_, err := Load("config_test/StrangeFeature.conf")
	if err == nil {
		t.Errorf("Loading unknown feature must fail but it didn't")
	} else if testing.Verbose() {
		fmt.Println(err)
	}
}

// testCreateArgs returns CreateArgs with the required NodeID. Create writes no key ring — the
// first mount generates the data key.
func testCreateArgs(filename string) *CreateArgs {
	return &CreateArgs{
		Filename: filename,
		NodeID:   "test-node",
	}
}

func TestCreateConfDefault(t *testing.T) {
	err := Create(testCreateArgs("config_test/tmp.conf"))
	if err != nil {
		t.Fatal(err)
	}
	c, err := Load("config_test/tmp.conf")
	if err != nil {
		t.Fatal(err)
	}
	// Check that all expected feature flags are set
	want := []flagIota{
		FlagGCMIV128, FlagDirIV, FlagEMENames, FlagLongNames,
		FlagRaw64,
	}
	for _, f := range want {
		if !c.IsFeatureFlagSet(f) {
			t.Errorf("Feature flag %q should be set but is not", knownFlags[f])
		}
	}
}

func TestCreateConfPlaintextnames(t *testing.T) {
	args := testCreateArgs("config_test/tmp.conf")
	args.PlaintextNames = true
	if err := Create(args); err != nil {
		t.Fatal(err)
	}
	c, err := Load("config_test/tmp.conf")
	if err != nil {
		t.Fatal(err)
	}
	// Check that all expected feature flags are set
	want := []flagIota{
		FlagGCMIV128,
	}
	for _, f := range want {
		if !c.IsFeatureFlagSet(f) {
			t.Errorf("Feature flag %q should be set but is not", knownFlags[f])
		}
	}
}

func TestCreateConfLongNameMax(t *testing.T) {
	args := testCreateArgs("config_test/tmp.conf")
	args.LongNameMax = 100
	if err := Create(args); err != nil {
		t.Fatal(err)
	}
	c, err := Load("config_test/tmp.conf")
	if err != nil {
		t.Fatal(err)
	}
	if !c.IsFeatureFlagSet(FlagLongNameMax) {
		t.Error("FlagLongNameMax should be set but is not")
	}
	if c.LongNameMax != args.LongNameMax {
		t.Errorf("wrong LongNameMax value: want=%d have=%d", args.LongNameMax, c.LongNameMax)
	}
}

func TestIsFeatureFlagKnown(t *testing.T) {
	// Test a few hardcoded values
	testKnownFlags := []string{"DirIV", "PlaintextNames", "EMENames", "GCMIV128", "LongNames"}
	// And also everything in knownFlags (yes, it is likely that we end up with
	// some duplicates. Does not matter.)
	for _, f := range knownFlags {
		testKnownFlags = append(testKnownFlags, f)
	}

	for _, f := range testKnownFlags {
		if !isFeatureFlagKnown(f) {
			t.Errorf("flag %q should be known", f)
		}
	}

	f := "StrangeFeatureFlag"
	if isFeatureFlagKnown(f) {
		t.Errorf("flag %q should be NOT known", f)
	}
}

// A validation failure must carry the exit code that matches WHY it failed. An old on-disk format
// is DeprecatedFS ("migrate this filesystem"); a self-contradictory config is LoadConf. Reporting
// the second as the first told operators to migrate a filesystem that was merely corrupt.
func TestValidateExitCodes(t *testing.T) {
	good := func() *ConfFile {
		return &ConfFile{
			Version:      contentenc.CurrentVersion,
			FeatureFlags: []string{knownFlags[FlagGCMIV128]},
			NodeID:       "node-1",
		}
	}
	if err := good().Validate(); err != nil {
		t.Fatalf("baseline config should validate: %v", err)
	}

	codeOf := func(t *testing.T, err error) int {
		t.Helper()
		if err == nil {
			t.Fatal("expected an error")
		}
		e, ok := err.(exitcodes.Err)
		if !ok {
			t.Fatalf("error does not carry an exit code: %v", err)
		}
		return e.Code()
	}

	old := good()
	old.Version = contentenc.CurrentVersion - 1
	if got := codeOf(t, old.Validate()); got != exitcodes.DeprecatedFS {
		t.Errorf("old format: exit code = %d, want DeprecatedFS (%d)", got, exitcodes.DeprecatedFS)
	}

	// Contradictory flags, current version: malformed, not deprecated.
	bad := good()
	bad.FeatureFlags = append(bad.FeatureFlags, knownFlags[FlagXChaCha20Poly1305])
	if got := codeOf(t, bad.Validate()); got != exitcodes.LoadConf {
		t.Errorf("conflicting flags: exit code = %d, want LoadConf (%d)", got, exitcodes.LoadConf)
	}

	unknown := good()
	unknown.FeatureFlags = append(unknown.FeatureFlags, "NoSuchFlag")
	if got := codeOf(t, unknown.Validate()); got != exitcodes.LoadConf {
		t.Errorf("unknown flag: exit code = %d, want LoadConf (%d)", got, exitcodes.LoadConf)
	}
}
