// Package configfile reads and writes gocryptfs.conf does the key
// wrapping.
package configfile

import (
	"encoding/json"
	"fmt"
	"path/filepath"
	"syscall"

	"os"

	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

const (
	// ConfDefaultName is the default configuration file name.
	// The dot "." is not used in base64url (RFC4648), hence
	// we can never clash with an encrypted file.
	ConfDefaultName = "gocryptfs.conf"
)

// ConfFile is the content of a config file.
type ConfFile struct {
	// Version is the On-Disk-Format version this filesystem uses
	Version uint16
	// FeatureFlags is a list of feature flags this filesystem has enabled.
	// If gocryptfs encounters a feature flag it does not support, it will refuse
	// mounting. This mechanism is analogous to the ext4 feature flags that are
	// stored in the superblock.
	FeatureFlags []string
	// NodeID is the unique identifier for this host/mount
	NodeID string
	// GatewayHost is the host:port of the TrustedGateway that wraps and unwraps
	// our data keys
	GatewayHost string
	// MockAWS uses a mock AWS connection for development
	MockAWS bool `json:",omitempty"`
	// MockKMS uses a mock KMS for development
	MockKMS  bool `json:",omitempty"`
	IsSearch bool `json:",omitempty"`
	// LongNameMax corresponds to the -longnamemax flag
	LongNameMax uint8 `json:",omitempty"`
	// Filename is the name of the config file. Not exported to JSON.
	filename string
}

// CreateArgs exists because the argument list to Create became too long.
type CreateArgs struct {
	Filename           string
	PlaintextNames     bool
	DeterministicNames bool
	XChaCha20Poly1305  bool
	NodeID             string
	GatewayHost        string
	MockAWS            bool
	MockKMS            bool
	IsSearch           bool
	LongNameMax        uint8
}

// Create - create a new config and write it to "Filename". No key ring is written: the first
// mount generates the data key and creates the key-ring file (see keyring.go).
func Create(args *CreateArgs) error {
	if args.NodeID == "" {
		// The NodeID scopes the keyspace for the first mount's generate and every later
		// unwrap; initDir resolves it, Create must not mint a different one.
		return fmt.Errorf("NodeID is required")
	}
	cf := ConfFile{
		filename:    args.Filename,
		Version:     contentenc.CurrentVersion,
		NodeID:      args.NodeID,
		GatewayHost: args.GatewayHost,
		MockAWS:     args.MockAWS,
		MockKMS:     args.MockKMS,
		IsSearch:    args.IsSearch,
	}

	// Feature flags
	if args.XChaCha20Poly1305 {
		cf.setFeatureFlag(FlagXChaCha20Poly1305)
	} else {
		// 128-bit IVs are mandatory for AES-GCM (default is 96!) and AES-SIV,
		// XChaCha20Poly1305 uses even an even longer IV of 192 bits.
		cf.setFeatureFlag(FlagGCMIV128)
	}
	if args.PlaintextNames {
		cf.setFeatureFlag(FlagPlaintextNames)
	} else {
		if !args.DeterministicNames {
			cf.setFeatureFlag(FlagDirIV)
		}
		// 0 means to *use* the default (which means we don't have to save it), and
		// 255 *is* the default, which means we don't have to save it either.
		if args.LongNameMax != 0 && args.LongNameMax != 255 {
			cf.LongNameMax = args.LongNameMax
			cf.setFeatureFlag(FlagLongNameMax)
		}
		cf.setFeatureFlag(FlagEMENames)
		cf.setFeatureFlag(FlagLongNames)
		cf.setFeatureFlag(FlagRaw64)
	}
	// Write file to disk
	return cf.WriteFile()
}

// Load loads and parses the config file at "filename". The returned error carries the exit code
// the caller should use: OpenConf if the file could not be read, DeprecatedFS if the on-disk
// format is one this version cannot read, LoadConf if the contents are malformed.
func Load(filename string) (*ConfFile, error) {
	var cf ConfFile
	cf.filename = filename

	// Read from disk
	js, err := os.ReadFile(filename)
	if err != nil {
		return nil, exitcodes.NewErr(err.Error(), exitcodes.OpenConf)
	}
	if len(js) == 0 {
		return nil, exitcodes.NewErr("config file is empty", exitcodes.LoadConf)
	}

	// Unmarshal
	if err := json.Unmarshal(js, &cf); err != nil {
		tlog.Warn.Printf("Failed to unmarshal config file")
		return nil, exitcodes.NewErr(err.Error(), exitcodes.LoadConf)
	}

	if err := cf.Validate(); err != nil {
		return nil, err
	}

	// All good
	return &cf, nil
}

func (cf *ConfFile) setFeatureFlag(flag flagIota) {
	if cf.IsFeatureFlagSet(flag) {
		// Already set, ignore
		return
	}
	cf.FeatureFlags = append(cf.FeatureFlags, knownFlags[flag])
}

// WriteFile atomically replaces the config file.
func (cf *ConfFile) WriteFile() error {
	if err := cf.Validate(); err != nil {
		return err
	}
	return writeJSONAtomic(cf.filename, cf)
}

// writeJSONAtomic marshals "v" to "filename.tmp" and renames it over "filename", so an update
// replaces the file atomically and a reader never observes a half-written one. Shared by the
// config file and the key ring: both hold data a mount cannot recover from if it lands
// truncated, and both are only ever replaced, never edited in place.
func writeJSONAtomic(filename string, v interface{}) (err error) {
	tmp := filename + ".tmp"
	// 0400: these files should be kept secret and are never written in place.
	fd, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return err
	}
	// Clean up the tmp file on any failure: leaving it behind would make every later attempt
	// fail on the exclusive create above.
	fdOpen := true
	defer func() {
		if err != nil {
			if fdOpen {
				fd.Close()
			}
			os.Remove(tmp)
		}
	}()
	js, err := json.MarshalIndent(v, "", "\t")
	if err != nil {
		return err
	}

	if _, err = fd.Write(js); err != nil {
		return err
	}
	if err2 := fd.Sync(); err2 != nil {
		// This can happen on network drives: FRITZ.NAS mounted on MacOS returns
		// "operation not supported": https://github.com/rfjakob/gocryptfs/issues/390
		tlog.Warn.Printf("Warning: fsync failed: %v", err2)
		// Try sync instead
		syscall.Sync()
	}
	fdOpen = false
	if err = fd.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp, filename); err != nil {
		return err
	}
	// fsync the directory so the rename survives a crash. For the key ring this is what stops a
	// crash from reverting to an absent ring and regenerating a key over data already encrypted
	// under the lost one. Warning-only, like the file fsync.
	if dirfd, err2 := os.Open(filepath.Dir(filename)); err2 == nil {
		if err2 := dirfd.Sync(); err2 != nil {
			tlog.Warn.Printf("Warning: directory fsync failed: %v", err2)
		}
		dirfd.Close()
	}
	return nil
}

// ContentEncryption tells us which content encryption algorithm is selected
func (cf *ConfFile) ContentEncryption() (algo cryptocore.AEADTypeEnum, err error) {
	if err := cf.Validate(); err != nil {
		return cryptocore.AEADTypeEnum{}, err
	}
	if cf.IsFeatureFlagSet(FlagXChaCha20Poly1305) {
		return cryptocore.BackendXChaCha20Poly1305, nil
	}
	// If neither AES-SIV nor XChaCha are selected, we must be using AES-GCM
	return cryptocore.BackendGoGCM, nil
}
