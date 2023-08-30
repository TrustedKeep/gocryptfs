package main

import (
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// isEmptyDir checks if "dir" exists and is an empty directory.
// Returns an *os.PathError if Stat() on the path fails.
func isEmptyDir(dir string) error {
	err := isDir(dir)
	if err != nil {
		return err
	}
	entries, err := ioutil.ReadDir(dir)
	if err != nil {
		return err
	}
	if len(entries) == 0 {
		return nil
	}
	return fmt.Errorf("directory %s not empty", dir)
}

// isDir checks if "dir" exists and is a directory.
func isDir(dir string) error {
	fi, err := os.Stat(dir)
	if err != nil {
		return err
	}
	if !fi.IsDir() {
		return fmt.Errorf("%s is not a directory", dir)
	}
	return nil
}

// initDir handles "gocryptfs -init". It prepares a directory for use as a
// gocryptfs storage directory.
// In forward mode, this means creating the gocryptfs.conf and gocryptfs.diriv
// files in an empty directory.
// In reverse mode, we create .gocryptfs.reverse.conf and the directory does
// not need to be empty.
func initDir(args *argContainer) {
	err := isEmptyDir(args.cipherdir)
	if err != nil {
		tlog.Fatal.Printf("Invalid cipherdir: %v", err)
		os.Exit(exitcodes.CipherDir)
	}

	{
		err = configfile.Create(&configfile.CreateArgs{
			Filename:           args.config,
			PlaintextNames:     args.plaintextnames,
			DeterministicNames: args.deterministic_names,
			XChaCha20Poly1305:  args.xchacha,
			NodeID:             args.nodeID,
			MockAWS:            args.mockAWS,
			MockKMS:            args.mockKMS,
			BoundaryHost:       args.boundaryHost,
			KeyPool:            args.keyPool,
			LongNameMax:        args.longnamemax,
		})
		if err != nil {
			tlog.Fatal.Println(err)
			os.Exit(exitcodes.WriteConf)
		}
	}
	// Forward mode with filename encryption enabled needs a gocryptfs.diriv file
	// in the root dir
	if !args.plaintextnames && !args.deterministic_names {
		// Open cipherdir (following symlinks)
		dirfd, err := syscall.Open(args.cipherdir, syscall.O_DIRECTORY|syscallcompat.O_PATH, 0)
		if err == nil {
			err = nametransform.WriteDirIVAt(dirfd)
			syscall.Close(dirfd)
		}
		if err != nil {
			tlog.Fatal.Println(err)
			os.Exit(exitcodes.Init)
		}
	}
	mountArgs := ""
	fsName := "gocryptfs"
	tlog.Info.Printf(tlog.ColorGreen+"The %s filesystem has been created successfully."+tlog.ColorReset,
		fsName)
	wd, _ := os.Getwd()
	friendlyPath, _ := filepath.Rel(wd, args.cipherdir)
	if strings.HasPrefix(friendlyPath, "../") {
		// A relative path that starts with "../" is pretty unfriendly, just
		// keep the absolute path.
		friendlyPath = args.cipherdir
	}
	if strings.Contains(friendlyPath, " ") {
		friendlyPath = "\"" + friendlyPath + "\""
	}
	tlog.Info.Printf(tlog.ColorGrey+"You can now mount it using: %s%s %s MOUNTPOINT"+tlog.ColorReset,
		tlog.ProgramName, mountArgs, friendlyPath)
}
