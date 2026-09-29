package nametransform

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"syscall"

	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

const (
	// DirIVLen is identical to AES block size
	DirIVLen = 16
	// dirIVKeyIdxLen is the big-endian uint16 key-ring index that follows the IV.
	dirIVKeyIdxLen = 2
	// DirIVFileLen is the on-disk length of gocryptfs.diriv: the IV plus the key-ring index
	// of the key this directory's filenames are encrypted under. A filename is its own
	// ciphertext and lookup runs the cipher forward, so the reader has to choose a key before
	// it has anything to test — the directory's IV file is the one place the index arrives in
	// time.
	DirIVFileLen = DirIVLen + dirIVKeyIdxLen
	// DirIVFilename is the filename used to store directory IV.
	// Exported because we have to ignore this name in directory listing.
	DirIVFilename = "gocryptfs.diriv"
)

// ReadDirIVAt reads "gocryptfs.diriv" from the directory that is opened as "dirfd".
// Using the dirfd makes it immune to concurrent renames of the directory.
// Retries on EINTR.
//
// The IV and the index are returned separately: eme panics on a tweak that is not exactly 16
// bytes, and every caller feeds the IV straight into EncryptName/DecryptName.
func (n *NameTransform) ReadDirIVAt(dirfd int) (iv []byte, keyIdx uint16, err error) {
	fdRaw, err := syscallcompat.Openat(dirfd, DirIVFilename,
		syscall.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, 0, err
	}
	fd := os.NewFile(uintptr(fdRaw), DirIVFilename)
	defer fd.Close()
	return n.fdReadDirIV(fd)
}

// allZeroDirIV is preallocated to quickly check if the data read from disk is all zero
var allZeroDirIV = make([]byte, DirIVLen)

// fdReadDirIV reads and verifies the DirIV from an opened gocryptfs.diriv file.
//
// The all-zero check inverts with -deterministic-names: there all-zero is the only legal IV,
// everywhere else it is a corruption signal.
func (n *NameTransform) fdReadDirIV(fd *os.File) (iv []byte, keyIdx uint16, err error) {
	// We want to detect if the file is bigger than DirIVFileLen, so
	// make the buffer 1 byte bigger than necessary.
	buf := make([]byte, DirIVFileLen+1)
	c, err := fd.Read(buf)
	if err != nil && err != io.EOF {
		return nil, 0, fmt.Errorf("read failed: %v", err)
	}
	buf = buf[0:c]
	if len(buf) != DirIVFileLen {
		return nil, 0, fmt.Errorf("wanted %d bytes, got %d", DirIVFileLen, len(buf))
	}
	iv = buf[:DirIVLen]
	if bytes.Equal(iv, allZeroDirIV) != n.deterministicNames {
		if n.deterministicNames {
			return nil, 0, fmt.Errorf("diriv is not all-zero but -deterministic-names is in effect")
		}
		return nil, 0, fmt.Errorf("diriv is all-zero")
	}
	return iv, binary.BigEndian.Uint16(buf[DirIVLen:]), nil
}

// WriteDirIVAt - create a new gocryptfs.diriv file in the directory opened at
// "dirfd", stamped with the key-ring index its filenames will be encrypted under.
// On error we try to delete the incomplete file.
// This function is exported because it is used from fusefrontend, main,
// and also the automated tests.
// deterministicNames writes an all-zero IV.
func WriteDirIVAt(dirfd int, keyIdx uint16, deterministicNames bool) error {
	record := make([]byte, DirIVFileLen)
	if !deterministicNames {
		copy(record, cryptocore.RandBytes(DirIVLen))
	}
	binary.BigEndian.PutUint16(record[DirIVLen:], keyIdx)
	// 0400 permissions: gocryptfs.diriv should never be modified after creation.
	// Don't use "os.WriteFile", it causes trouble on NFS:
	// https://github.com/rfjakob/gocryptfs/commit/7d38f80a78644c8ec4900cc990bfb894387112ed
	fd, err := syscallcompat.Openat(dirfd, DirIVFilename, os.O_WRONLY|os.O_CREATE|os.O_EXCL, dirivPerms)
	if err != nil {
		tlog.Warn.Printf("WriteDirIV: Openat: %v", err)
		return err
	}
	// Wrap the fd in an os.File - we need the write retry logic.
	f := os.NewFile(uintptr(fd), DirIVFilename)
	_, err = f.Write(record)
	if err != nil {
		f.Close()
		// It is normal to get ENOSPC here
		if !syscallcompat.IsENOSPC(err) {
			tlog.Warn.Printf("WriteDirIV: Write: %v", err)
		}
		// Delete incomplete gocryptfs.diriv file
		syscallcompat.Unlinkat(dirfd, DirIVFilename, 0)
		return err
	}
	err = f.Close()
	if err != nil {
		tlog.Warn.Printf("WriteDirIV: Close: %v", err)
		// Delete incomplete gocryptfs.diriv file
		syscallcompat.Unlinkat(dirfd, DirIVFilename, 0)
		return err
	}
	return nil
}
