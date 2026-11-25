// Package fusefrontend interfaces directly with the go-fuse library.
package fusefrontend

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fuse"

	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// -1 as uint32
const minus1 = ^uint32(0)

// We store encrypted xattrs under this prefix plus the base64-encoded
// encrypted original name.
var xattrStorePrefix = "user.gocryptfs."

// xattrKeyIdxPrefix names the per-inode marker "user.gocryptfs_keyidx.<n>": the key-ring index the
// inode's xattr names are encrypted under, stamped by its first encrypted xattr. The index is in the
// name so that Listxattr, which needs no read permission, can find it.
const xattrKeyIdxPrefix = "user.gocryptfs_keyidx."

// We get one read of this xattr for each write -
// see https://github.com/rfjakob/gocryptfs/issues/515 for details.
var xattrCapability = "security.capability"

// isAcl returns true if the attribute name is for storing ACLs
//
// ACLs are passed through without encryption
func isAcl(attr string) bool {
	return attr == "system.posix_acl_access" || attr == "system.posix_acl_default"
}

// GetXAttr - FUSE call. Reads the value of extended attribute "attr".
//
// This function is symlink-safe through Fgetxattr.
func (n *Node) Getxattr(ctx context.Context, attr string, dest []byte) (uint32, syscall.Errno) {
	rn := n.rootNode()
	// If we are not mounted with -suid, reading the capability xattr does not
	// make a lot of sense, so reject the request and gain a massive speedup.
	// See https://github.com/rfjakob/gocryptfs/issues/515 .
	if !rn.args.Suid && attr == xattrCapability {
		// Returning EOPNOTSUPP is what we did till
		// ca9e912a28b901387e1dbb85f6c531119f2d5ef2 "fusefrontend: drop xattr user namespace restriction"
		// and it did not cause trouble. Seems cleaner than saying ENODATA.
		return 0, syscall.EOPNOTSUPP
	}
	var data []byte
	// ACLs are passed through without encryption
	if isAcl(attr) {
		var errno syscall.Errno
		data, errno = n.getXAttr(attr)
		if errno != 0 {
			return minus1, errno
		}
	} else {
		// encrypted user xattr
		keyIdx, ok, errno := n.xattrKeyIdx()
		if errno != 0 {
			return 0, errno
		}
		if !ok {
			return 0, syscall.ENODATA
		}
		cAttr, err := rn.encryptXattrName(attr, keyIdx)
		if err != nil {
			return minus1, syscall.EIO
		}
		cData, errno := n.getXAttr(cAttr)
		if errno != 0 {
			return 0, errno
		}
		data, err = rn.decryptXattrValue(cData)
		if err != nil {
			tlog.Warn.Printf("GetXAttr: %v", err)
			return minus1, syscall.EIO
		}
	}
	// Caller passes size zero to find out how large their buffer should be
	if len(dest) == 0 {
		return uint32(len(data)), 0
	}
	if len(dest) < len(data) {
		return minus1, syscall.ERANGE
	}
	l := copy(dest, data)
	return uint32(l), 0
}

// SetXAttr - FUSE call. Set extended attribute.
//
// This function is symlink-safe through Fsetxattr.
func (n *Node) Setxattr(ctx context.Context, attr string, data []byte, flags uint32) syscall.Errno {
	rn := n.rootNode()
	flags = uint32(filterXattrSetFlags(int(flags)))

	// ACLs are passed through without encryption
	if isAcl(attr) {
		// result of setting an acl depends on the user doing it
		var context *fuse.Context
		if rn.args.PreserveOwner {
			context = toFuseCtx(ctx)
		}
		return n.setXAttr(context, attr, data, flags)
	}

	keyIdx, errno := n.xattrKeyIdxForSet()
	if errno != 0 {
		return errno
	}
	cAttr, err := rn.encryptXattrName(attr, keyIdx)
	if err != nil {
		return xattrNameErrno(err)
	}
	cData := rn.encryptXattrValue(data)
	return n.setXAttr(nil, cAttr, cData, flags)
}

// RemoveXAttr - FUSE call.
//
// This function is symlink-safe through Fremovexattr.
func (n *Node) Removexattr(ctx context.Context, attr string) syscall.Errno {
	rn := n.rootNode()

	// ACLs are passed through without encryption
	if isAcl(attr) {
		return n.removeXAttr(attr)
	}

	keyIdx, ok, errno := n.xattrKeyIdx()
	if errno != 0 {
		return errno
	}
	if !ok {
		return syscall.ENODATA
	}
	cAttr, err := rn.encryptXattrName(attr, keyIdx)
	if err != nil {
		return xattrNameErrno(err)
	}
	return n.removeXAttr(cAttr)
}

// ListXAttr - FUSE call. Lists extended attributes on the file at "relPath".
//
// This function is symlink-safe through Flistxattr.
func (n *Node) Listxattr(ctx context.Context, dest []byte) (uint32, syscall.Errno) {
	cNames, errno := n.listXAttr()
	if errno != 0 {
		return 0, errno
	}
	keyIdx, haveKeyIdx, err := parseXattrKeyIdx(cNames)
	if err != nil {
		tlog.Warn.Printf("ListXAttr: %v", err)
		return 0, syscall.EIO
	}
	rn := n.rootNode()
	var buf bytes.Buffer
	for _, curName := range cNames {
		// ACLs are passed through without encryption
		if isAcl(curName) {
			buf.WriteString(curName + "\000")
			continue
		}
		if !strings.HasPrefix(curName, xattrStorePrefix) {
			continue
		}
		if !haveKeyIdx {
			tlog.Warn.Printf("ListXAttr: %q has no key-index marker to decrypt it under", curName)
			rn.reportMitigatedCorruption(curName)
			continue
		}
		name, err := rn.decryptXattrName(curName, keyIdx)
		if errors.Is(err, nametransform.ErrKeyMissing) {
			return 0, nameErrno(err)
		}
		if err != nil {
			tlog.Warn.Printf("ListXAttr: invalid xattr name %q: %v", curName, err)
			rn.reportMitigatedCorruption(curName)
			continue
		}
		// We *used to* encrypt ACLs, which caused a lot of problems.
		if isAcl(name) {
			tlog.Warn.Printf("ListXAttr: ignoring deprecated encrypted ACL %q = %q", curName, name)
			rn.reportMitigatedCorruption(curName)
			continue
		}
		buf.WriteString(name + "\000")
	}
	// Caller passes size zero to find out how large their buffer should be
	if len(dest) == 0 {
		return uint32(buf.Len()), 0
	}
	if buf.Len() > len(dest) {
		return minus1, syscall.ERANGE
	}
	return uint32(copy(dest, buf.Bytes())), 0
}

// parseXattrKeyIdx finds the key-index marker among an inode's backing xattr names. ok is false when
// there is none, which means the inode has no encrypted xattrs.
func parseXattrKeyIdx(cNames []string) (keyIdx uint16, ok bool, err error) {
	for _, cName := range cNames {
		s, found := strings.CutPrefix(cName, xattrKeyIdxPrefix)
		if !found {
			continue
		}
		if ok {
			return 0, false, fmt.Errorf("duplicate xattr key-index marker %q", cName)
		}
		v, err := strconv.ParseUint(s, 10, 16)
		if err != nil {
			return 0, false, fmt.Errorf("malformed xattr key-index marker %q", cName)
		}
		keyIdx, ok = uint16(v), true
	}
	return keyIdx, ok, nil
}

// xattrKeyIdx reads the inode's xattr key-index marker.
func (n *Node) xattrKeyIdx() (keyIdx uint16, ok bool, errno syscall.Errno) {
	cNames, errno := n.listXAttr()
	if errno != 0 {
		return 0, false, errno
	}
	keyIdx, ok, err := parseXattrKeyIdx(cNames)
	if err != nil {
		tlog.Warn.Printf("xattr: %v", err)
		return 0, false, syscall.EIO
	}
	return keyIdx, ok, 0
}

// xattrKeyIdxForSet returns the inode's xattr key index, stamping the current write index on an
// inode that has no marker yet.
func (n *Node) xattrKeyIdxForSet() (uint16, syscall.Errno) {
	if keyIdx, ok, errno := n.xattrKeyIdx(); errno != 0 || ok {
		return keyIdx, errno
	}
	rn := n.rootNode()
	rn.xattrKeyIdxLock.Lock()
	defer rn.xattrKeyIdxLock.Unlock()
	if keyIdx, ok, errno := n.xattrKeyIdx(); errno != 0 || ok {
		return keyIdx, errno
	}
	keyIdx := rn.nameTransform.WriteKeyIdx()
	return keyIdx, n.setXAttr(nil, xattrKeyIdxPrefix+strconv.Itoa(int(keyIdx)), nil, 0)
}

// xattrNameErrno maps an xattr-name encryption failure. A missing key is EIO, like every other
// unreadable-under-this-mount path; anything else is a malformed name, which stays EINVAL.
func xattrNameErrno(err error) syscall.Errno {
	if errors.Is(err, nametransform.ErrKeyMissing) {
		return syscall.EIO
	}
	return syscall.EINVAL
}
