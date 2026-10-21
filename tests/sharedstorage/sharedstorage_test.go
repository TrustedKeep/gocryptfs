// test gocryptfs cipherdir mounted multiple times at the same time
package sharedstorage

import (
	"fmt"
	"path/filepath"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

type testCase struct {
	cipherdir string
	mnt1      string
	mnt2      string
}

func newTestCase(t *testing.T) *testCase {
	tc := testCase{}
	tc.cipherdir = test_helpers.InitFS(t)
	tc.mnt1 = tc.cipherdir + ".mnt1"
	tc.mnt2 = tc.cipherdir + ".mnt2"
	mountSharedstorage(t, tc.cipherdir, tc.mnt1)
	mountSharedstorage(t, tc.cipherdir, tc.mnt2)
	t.Logf("newTestCase: cipherdir=%q", tc.cipherdir)
	return &tc
}

// mountSharedstorage mounts `cipherdir` on `mnt` with `-sharedstorage` and
// unmounts it when the test ends, so a failed second mount does not leak the first.
func mountSharedstorage(t *testing.T, cipherdir string, mnt string) {
	test_helpers.MountOrFatal(t, cipherdir, mnt, "-sharedstorage", "-node-id="+filepath.Base(mnt))
	t.Cleanup(func() {
		if err := test_helpers.UnmountErr(mnt); err != nil {
			t.Error(err)
		}
	})
}

func TestDirUnlink(t *testing.T) {
	tc := newTestCase(t)

	// Create dir via mnt1
	if err := unix.Mkdir(tc.mnt1+"/foo", 0700); err != nil {
		t.Fatal(err)
	}
	// Replace dir with file via mnt2
	if err := unix.Rmdir(tc.mnt2 + "/foo"); err != nil {
		t.Fatal(err)
	}
	if fd, err := unix.Open(tc.mnt2+"/foo", unix.O_CREAT|unix.O_WRONLY|unix.O_TRUNC, 0600); err != nil {
		t.Fatal(err)
	} else {
		unix.Close(fd)
	}
	// Try to unlink via mnt1
	if err := unix.Unlink(tc.mnt1 + "/foo"); err != nil {
		t.Fatal(err)
	}
}

// TestStaleHardlinks always failed before
// https://review.gerrithub.io/c/hanwen/go-fuse/+/513646/2
func TestStaleHardlinks(t *testing.T) {
	tc := newTestCase(t)

	link0 := tc.mnt1 + "/link0"
	if fd, err := unix.Open(link0, unix.O_CREAT|unix.O_WRONLY|unix.O_TRUNC, 0600); err != nil {
		t.Fatal(err)
	} else {
		unix.Close(fd)
	}
	// Create hardlinks via mnt1
	for i := 1; i < 20; i++ {
		linki := fmt.Sprintf(tc.mnt1+"/link%d", i)
		if err := unix.Link(link0, linki); err != nil {
			t.Fatal(err)
		}
	}
	// Delete hardlinks via mnt2
	for i := 1; i < 20; i++ {
		linki := fmt.Sprintf(tc.mnt2+"/link%d", i)
		if err := unix.Unlink(linki); err != nil {
			t.Fatal(err)
		}
	}
	// Open link0 via mnt1
	fd, err := unix.Open(link0, unix.O_RDONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	unix.Close(fd)
}
