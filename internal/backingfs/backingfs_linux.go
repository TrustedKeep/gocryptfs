// Package backingfs decides whether the filesystem under a cipherdir is safe for -sharedstorage.
package backingfs

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/moby/sys/mountinfo"
	"golang.org/x/sys/unix"
)

var localFS = map[string]bool{
	"ext2":     true,
	"ext3":     true,
	"ext4":     true,
	"xfs":      true,
	"btrfs":    true,
	"tmpfs":    true,
	"zfs":      true,
	"f2fs":     true,
	"bcachefs": true,
	"jfs":      true,
}

// CheckShared returns an error unless the filesystem holding cipherdir is one -sharedstorage can vouch for.
func CheckShared(cipherdir string) error {
	path, err := filepath.Abs(cipherdir)
	if err != nil {
		return err
	}
	path, err = filepath.EvalSymlinks(path)
	if err != nil {
		return err
	}
	id, err := mountID(path)
	if err != nil {
		return err
	}
	f, err := os.Open("/proc/self/mountinfo")
	if err != nil {
		return err
	}
	defer f.Close()
	return checkShared(path, id, f)
}

// mountID returns the mountinfo ID of the mount holding path, or -1 if the kernel does not report it. Unlike
// a longest-prefix match, it is not fooled by a later mount covering a parent directory.
func mountID(path string) (int, error) {
	fd, err := unix.Open(path, unix.O_PATH|unix.O_CLOEXEC, 0)
	if err != nil {
		return -1, &os.PathError{Op: "open", Path: path, Err: err}
	}
	defer unix.Close(fd)
	b, err := os.ReadFile("/proc/self/fdinfo/" + strconv.Itoa(fd))
	if err != nil {
		return -1, err
	}
	for _, line := range strings.Split(string(b), "\n") {
		if v, ok := strings.CutPrefix(line, "mnt_id:"); ok {
			return strconv.Atoi(strings.TrimSpace(v))
		}
	}
	return -1, nil
}

// checkShared vets the mount with ID id, or the one found by findMount when id is -1.
func checkShared(path string, id int, r io.Reader) error {
	mounts, err := mountinfo.GetMountsFromReader(r, nil)
	if err != nil {
		return err
	}
	var m *mountinfo.Info
	if id >= 0 {
		for _, mi := range mounts {
			if mi.ID == id {
				m = mi
				break
			}
		}
	} else {
		m = findMount(filepath.Clean(path), mounts)
	}
	if m == nil {
		return fmt.Errorf("no mount found for %q in mountinfo", path)
	}
	if reason := refusal(m); reason != "" {
		return fmt.Errorf("%s at %q is not safe for -sharedstorage: %s", m.FSType, m.Mountpoint, reason)
	}
	return nil
}

// findMount returns the mount whose mount point is the longest prefix of path. Of mounts stacked on one
// point, the last listed is the visible one.
func findMount(path string, mounts []*mountinfo.Info) *mountinfo.Info {
	var best *mountinfo.Info
	for _, m := range mounts {
		if m.Mountpoint != "/" && path != m.Mountpoint && !strings.HasPrefix(path, m.Mountpoint+"/") {
			continue
		}
		if best == nil || len(m.Mountpoint) >= len(best.Mountpoint) {
			best = m
		}
	}
	return best
}

func refusal(m *mountinfo.Info) string {
	switch {
	case localFS[m.FSType]:
		return ""
	case m.FSType == "nfs4":
		return nfs4Refusal(m.Options + "," + m.VFSOptions)
	case m.FSType == "nfs":
		return "NFSv3 and older are not supported, needs nfs4 with vers=4.1 or later"
	case m.FSType == "cifs" || m.FSType == "smb3":
		return "SMB is not supported"
	case strings.HasPrefix(m.FSType, "fuse"):
		return "FUSE filesystems are not supported"
	}
	return "unrecognized filesystem"
}

func nfs4Refusal(opts string) string {
	sawVers := false
	for _, o := range strings.Split(opts, ",") {
		k, v, _ := strings.Cut(o, "=")
		switch k {
		case "soft", "softerr":
			return "mounted " + k + ", needs hard"
		case "nolock":
			return "mounted nolock, needs locks that reach the server"
		case "nocto":
			return "mounted nocto, needs close-to-open consistency to see other mounts' key-ring entries"
		case "local_lock":
			if v != "none" {
				return o + ", needs local_lock=none"
			}
		case "vers":
			sawVers = true
			if !versAtLeast41(v) {
				return o + ", needs vers=4.1 or later"
			}
		}
	}
	if !sawVers {
		return "no vers option, needs vers=4.1 or later"
	}
	return ""
}

func versAtLeast41(v string) bool {
	majStr, minStr, _ := strings.Cut(v, ".")
	major, err := strconv.Atoi(majStr)
	if err != nil {
		return false
	}
	minor, _ := strconv.Atoi(minStr)
	return major > 4 || major == 4 && minor >= 1
}
