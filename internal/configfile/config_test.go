package configfile

import (
	"fmt"
	"testing"
)

func TestLoadV2Feature(t *testing.T) {
	_, err := Load("config_test/PlaintextNames.conf")
	if err != nil {
		t.Errorf("Could not load v2 PlaintextNames config file: %v", err)
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

func TestCreateConfDefault(t *testing.T) {
	err := Create(&CreateArgs{Filename: "config_test/tmp.conf"})
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
		FlagRaw64, FlagHKDF,
	}
	for _, f := range want {
		if !c.IsFeatureFlagSet(f) {
			t.Errorf("Feature flag %q should be set but is not", knownFlags[f])
		}
	}
}

func TestCreateConfPlaintextnames(t *testing.T) {
	err := Create(&CreateArgs{
		Filename:       "config_test/tmp.conf",
		PlaintextNames: true})
	if err != nil {
		t.Fatal(err)
	}
	c, err := Load("config_test/tmp.conf")
	if err != nil {
		t.Fatal(err)
	}
	// Check that all expected feature flags are set
	want := []flagIota{
		FlagGCMIV128, FlagHKDF,
	}
	for _, f := range want {
		if !c.IsFeatureFlagSet(f) {
			t.Errorf("Feature flag %q should be set but is not", knownFlags[f])
		}
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
