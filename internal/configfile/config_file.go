// Package configfile reads and writes gocryptfs.conf does the key
// wrapping.
package configfile

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/rand"
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
	// BoundaryHost is the host:port of the Boundary instance that will retrieve
	// our encryption keys
	BoundaryHost string
	// MockAWS uses a mock AWS connection for development
	MockAWS bool
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
	BoundaryHost       string
	MockAWS            bool `json:",omitempty"`
}

// Create - create a new config and write it to "Filename".
func Create(args *CreateArgs) error {
	cf := ConfFile{
		filename:     args.Filename,
		Version:      contentenc.CurrentVersion,
		NodeID:       args.NodeID,
		BoundaryHost: args.BoundaryHost,
		MockAWS:      args.MockAWS,
	}

	if cf.NodeID == "" {
		data := make([]byte, 16)
		rand.Read(data)
		cf.NodeID = hex.EncodeToString(data)
	}

	// Feature flags
	cf.setFeatureFlag(FlagHKDF)
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
		cf.setFeatureFlag(FlagEMENames)
		cf.setFeatureFlag(FlagLongNames)
		cf.setFeatureFlag(FlagRaw64)
	}
	// Write file to disk
	return cf.WriteFile()
}

// Load loads and parses the config file at "filename".
func Load(filename string) (*ConfFile, error) {
	var cf ConfFile
	cf.filename = filename

	// Read from disk
	js, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	if len(js) == 0 {
		return nil, fmt.Errorf("Config file is empty")
	}

	// Unmarshal
	err = json.Unmarshal(js, &cf)
	if err != nil {
		tlog.Warn.Printf("Failed to unmarshal config file")
		return nil, err
	}

	if err := cf.Validate(); err != nil {
		return nil, exitcodes.NewErr(err.Error(), exitcodes.DeprecatedFS)
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

// WriteFile - write out config in JSON format to file "filename.tmp"
// then rename over "filename".
// This way a password change atomically replaces the file.
func (cf *ConfFile) WriteFile() error {
	if err := cf.Validate(); err != nil {
		return err
	}
	tmp := cf.filename + ".tmp"
	// 0400 permissions: gocryptfs.conf should be kept secret and never be written to.
	fd, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0400)
	if err != nil {
		return err
	}
	js, err := json.MarshalIndent(cf, "", "\t")
	if err != nil {
		return err
	}
	// For convenience for the user, add a newline at the end.
	js = append(js, '\n')
	_, err = fd.Write(js)
	if err != nil {
		return err
	}
	err = fd.Sync()
	if err != nil {
		// This can happen on network drives: FRITZ.NAS mounted on MacOS returns
		// "operation not supported": https://github.com/rfjakob/gocryptfs/issues/390
		tlog.Warn.Printf("Warning: fsync failed: %v", err)
		// Try sync instead
		syscall.Sync()
	}
	err = fd.Close()
	if err != nil {
		return err
	}
	err = os.Rename(tmp, cf.filename)
	return err
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
