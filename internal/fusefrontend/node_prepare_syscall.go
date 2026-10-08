package fusefrontend

import (
	"errors"
	"syscall"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"

	"github.com/hanwen/go-fuse/v2/fs"

	"github.com/rfjakob/gocryptfs/v2/internal/syscallcompat"
)

// prepareAtSyscall returns a (dirfd, cName) pair that can be used
// with the "___at" family of system calls (openat, fstatat, unlinkat...) to
// access the backing encrypted child file.
func (n *Node) prepareAtSyscall(child string) (dirfd int, cName string, errno syscall.Errno) {
	if child == "" {
		tlog.Warn.Printf("BUG: prepareAtSyscall: child=%q, should have called prepareAtSyscallMyself", child)
		return n.prepareAtSyscallMyself()
	}

	rn := n.rootNode()

	// All filesystem operations go through here, so this is a good place
	// to reset the idle marker.
	rn.IsIdle.Store(false)

	if n.IsRoot() && rn.isFiltered(child) {
		return -1, "", syscall.EPERM
	}

	var encryptName func(int, string, []byte, uint16) (string, error)
	if !rn.args.PlaintextNames {
		encryptName = func(dirfd int, child string, iv []byte, keyIdx uint16) (cName string, err error) {
			// Badname allowed, try to determine filenames
			if rn.nameTransform.HaveBadnamePatterns() {
				return rn.nameTransform.EncryptAndHashBadName(child, iv, keyIdx, dirfd)
			}
			return rn.nameTransform.EncryptAndHashName(child, iv, keyIdx)
		}
	}

	// Cache lookup
	var iv []byte
	var keyIdx uint16
	dirfd, iv, keyIdx = rn.dirCache.Lookup(n)
	if dirfd > 0 {
		if rn.args.PlaintextNames {
			return dirfd, child, 0
		}
		var err error
		cName, err = encryptName(dirfd, child, iv, keyIdx)
		if err != nil {
			syscall.Close(dirfd)
			return -1, "", nameErrno(err)
		}
		return
	}

	// Slowpath: Open ourselves & read diriv
	parentDirfd, myCName, errno := n.prepareAtSyscallMyself()
	if errno != 0 {
		return
	}
	defer syscall.Close(parentDirfd)

	dirfd, err := syscallcompat.Openat(parentDirfd, myCName, syscall.O_NOFOLLOW|syscall.O_DIRECTORY|syscallcompat.O_PATH, 0)
	if err != nil {
		return -1, "", fs.ToErrno(err)
	}

	// Cache store
	if !rn.args.PlaintextNames {
		var err error
		iv, keyIdx, err = rn.nameTransform.ReadDirIVAt(dirfd)
		if err != nil {
			syscall.Close(dirfd)
			return -1, "", nameErrno(err)
		}
	}
	rn.dirCache.Store(n, dirfd, iv, keyIdx)

	if rn.args.PlaintextNames {
		return dirfd, child, 0
	}

	cName, err = encryptName(dirfd, child, iv, keyIdx)
	if err != nil {
		syscall.Close(dirfd)
		return -1, "", nameErrno(err)
	}

	return
}

// nameErrno maps a name-transform failure to an errno. A name that is too long or invalid already
// carries one and keeps it; a key-ring index this mount has no key for does not, and go-fuse would
// answer ENOSYS for it rather than the EIO an unavailable key is documented to produce.
//
// Fatal is the level, not the outcome: -q must not hide why a subtree stopped resolving, and Warn
// would turn it into a panic under -wpanic.
func nameErrno(err error) syscall.Errno {
	var errno syscall.Errno
	if errors.As(err, &errno) {
		return errno
	}
	tlog.Fatal.Printf("prepareAtSyscall: %v", err)
	return syscall.EIO
}

func (n *Node) prepareAtSyscallMyself() (dirfd int, cName string, errno syscall.Errno) {
	dirfd = -1

	// Handle root node
	if n.IsRoot() {
		var err error
		rn := n.rootNode()
		// Open cipherdir (following symlinks)
		dirfd, err = syscallcompat.Open(rn.args.Cipherdir, syscall.O_DIRECTORY|syscallcompat.O_PATH, 0)
		if err != nil {
			return -1, "", fs.ToErrno(err)
		}
		return dirfd, ".", 0
	}

	// Otherwise convert to prepareAtSyscall of parent node
	myName, p1 := n.Parent()
	if p1 == nil || myName == "" {
		errno = syscall.ENOENT
		return
	}
	parent := toNode(p1.Operations())
	return parent.prepareAtSyscall(myName)
}
