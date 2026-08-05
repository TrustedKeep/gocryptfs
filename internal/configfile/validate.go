package configfile

import (
	"fmt"

	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
)

// badConf reports a config whose contents are self-contradictory or unsupported. This is a
// malformed config, NOT an old one: only a version mismatch means "deprecated filesystem", and
// conflating the two told operators to migrate a filesystem that was actually just corrupt.
func badConf(format string, a ...interface{}) error {
	return exitcodes.NewErr(fmt.Sprintf(format, a...), exitcodes.LoadConf)
}

// Validate that the combination of settings makes sense and is supported.
//
// The returned error carries the exit code the caller should use: DeprecatedFS for an
// unreadable on-disk format, LoadConf for anything else.
func (cf *ConfFile) Validate() error {
	if cf.Version != contentenc.CurrentVersion {
		return exitcodes.NewErr(
			fmt.Sprintf("unsupported on-disk format %d (this version reads format %d only)",
				cf.Version, contentenc.CurrentVersion),
			exitcodes.DeprecatedFS)
	}
	// All feature flags that are in the config file are known?
	for _, flag := range cf.FeatureFlags {
		if !isFeatureFlagKnown(flag) {
			return badConf("unknown feature flag %q", flag)
		}
	}
	// File content encryption
	{
		if cf.IsFeatureFlagSet(FlagXChaCha20Poly1305) && cf.IsFeatureFlagSet(FlagAESSIV) {
			return badConf("can't have both XChaCha20Poly1305 and AESSIV feature flags")
		}
		if cf.IsFeatureFlagSet(FlagAESSIV) && !cf.IsFeatureFlagSet(FlagGCMIV128) {

			return badConf("AESSIV requires GCMIV128 feature flag")
		}
		if cf.IsFeatureFlagSet(FlagXChaCha20Poly1305) && cf.IsFeatureFlagSet(FlagGCMIV128) {
			return badConf("XChaCha20Poly1305 conflicts with GCMIV128 feature flag")
		}
		// The absence of other flags means AES-GCM (oldest algorithm)
		if !cf.IsFeatureFlagSet(FlagXChaCha20Poly1305) && !cf.IsFeatureFlagSet(FlagAESSIV) {
			if !cf.IsFeatureFlagSet(FlagGCMIV128) {
				return badConf("AES-GCM requires GCMIV128 feature flag")
			}
		}
	}
	// Filename encryption
	{
		if cf.IsFeatureFlagSet(FlagPlaintextNames) {
			if cf.IsFeatureFlagSet(FlagEMENames) {
				return badConf("PlaintextNames conflicts with EMENames feature flag")
			}
			if cf.IsFeatureFlagSet(FlagDirIV) {
				return badConf("PlaintextNames conflicts with DirIV feature flag")
			}
			if cf.IsFeatureFlagSet(FlagLongNames) {
				return badConf("PlaintextNames conflicts with LongNames feature flag")
			}
			if cf.IsFeatureFlagSet(FlagRaw64) {
				return badConf("PlaintextNames conflicts with Raw64 feature flag")
			}
			if cf.IsFeatureFlagSet(FlagLongNameMax) {
				return badConf("PlaintextNames conflicts with LongNameMax feature flag")
			}
		}
		if cf.IsFeatureFlagSet(FlagEMENames) {
			// All combinations of DirIV, LongNames, Raw64 allowed
		}
		if cf.LongNameMax != 0 && !cf.IsFeatureFlagSet(FlagLongNameMax) {
			return badConf("LongNameMax=%d but the LongNameMax feature flag is NOT set", cf.LongNameMax)
		}
		if cf.LongNameMax == 0 && cf.IsFeatureFlagSet(FlagLongNameMax) {
			return badConf("LongNameMax=0 but the LongNameMax feature flag IS set")
		}
	}
	return nil
}
