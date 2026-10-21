package fusefrontend

import (
	"os"
	"syscall"
	"time"

	"github.com/hanwen/go-fuse/v2/fs"
	"golang.org/x/sys/unix"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// xattrStampWait bounds how long a first-xattr stamp waits for another mount's.
const xattrStampWait = 10 * time.Second

// lockXattrStamp serializes stamping n's xattr key-index marker across every mount of the cipherdir,
// and returns the release. It revalidates n under the lock, since NFS caches xattr names.
func (n *Node) lockXattrStamp() (unlock func(), errno syscall.Errno) {
	f, err := n.rootNode().xattrLock()
	if err != nil {
		tlog.Warn.Printf("xattr: opening the key-index stamp lock: %v", err)
		return nil, syscall.EIO
	}
	dirfd, cName, errno := n.prepareAtSyscallMyself()
	if errno != 0 {
		return nil, errno
	}
	defer syscall.Close(dirfd)
	var st unix.Stat_t
	if err := unix.Fstatat(dirfd, cName, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		return nil, fs.ToErrno(err)
	}
	lk := unix.Flock_t{Type: unix.F_WRLCK, Start: int64(st.Ino % (1 << 62)), Len: 1}
	deadline := time.Now().Add(xattrStampWait)
	for {
		err = unix.FcntlFlock(f.Fd(), unix.F_OFD_SETLK, &lk)
		busy := err == unix.EAGAIN || err == unix.EACCES || err == unix.EINTR
		if !busy || !time.Now().Before(deadline) {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if err != nil {
		tlog.Warn.Printf("xattr: locking the key-index stamp: %v", err)
		return nil, syscall.EIO
	}
	var stx unix.Statx_t
	unix.Statx(dirfd, cName, unix.AT_SYMLINK_NOFOLLOW|unix.AT_STATX_FORCE_SYNC, unix.STATX_BASIC_STATS, &stx)
	return func() {
		lk.Type = unix.F_UNLCK
		unix.FcntlFlock(f.Fd(), unix.F_OFD_SETLK, &lk)
	}, 0
}

// xattrLock opens the stamp lock file once, retrying after a failure.
func (rn *RootNode) xattrLock() (*os.File, error) {
	rn.xattrLockMu.Lock()
	defer rn.xattrLockMu.Unlock()
	if rn.xattrLockFile == nil {
		f, err := os.OpenFile(configfile.XattrLockPath(rn.args.Cipherdir), os.O_RDWR|os.O_CREATE, 0600)
		if err != nil {
			return nil, err
		}
		rn.xattrLockFile = f
	}
	return rn.xattrLockFile, nil
}
