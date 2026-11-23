package fsck

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

func runFsck(t *testing.T, cDir string) int {
	cmd := exec.Command(test_helpers.GocryptfsBinary, "-fsck", "-mock-kms", cDir)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return test_helpers.ExtractCmdExitCode(cmd.Run())
}

// TestFsckTKFS checks that fsck unwraps the ring like a mount does.
func TestFsckTKFS(t *testing.T) {
	cDir := test_helpers.InitFS(t)
	pDir := cDir + ".mnt"
	test_helpers.MountOrFatal(t, cDir, pDir)
	if err := os.WriteFile(pDir+"/file", []byte("content"), 0600); err != nil {
		t.Fatal(err)
	}
	test_helpers.UnmountPanic(pDir)
	if code := runFsck(t, cDir); code != 0 {
		t.Fatalf("fsck exited %d, want 0", code)
	}
}

// TestFsckRefusesAMountedFilesystem holds the ring lock as a mount does; fsck must not run under it.
func TestFsckRefusesAMountedFilesystem(t *testing.T) {
	cDir := test_helpers.InitFS(t)
	lock, err := configfile.LockKeyRing(filepath.Join(cDir, configfile.ConfDefaultName), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer lock.Close()
	if code := runFsck(t, cDir); code != exitcodes.AlreadyMounted {
		t.Fatalf("fsck exited %d, want %d", code, exitcodes.AlreadyMounted)
	}
}

// TestTerabyteFile verifies that fsck does something intelligent when it hits
// a 1-terabyte sparse file (trying to read the whole file is not intelligent).
func TestTerabyteFile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("Only linux supports SEEK_DATA")
	}
	cDir := test_helpers.InitFS(t)
	pDir := cDir + ".mnt"
	test_helpers.MountOrFatal(t, cDir, pDir)
	veryBigFile := pDir + "/veryBigFile"
	fd, err := os.Create(veryBigFile)
	if err != nil {
		t.Fatal(err)
	}
	var oneTiB int64 = 1024 * 1024 * 1024 * 1024
	_, err = fd.WriteAt([]byte("foobar"), oneTiB)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := fd.Stat()
	if err != nil {
		t.Fatal(err)
	}
	fd.Close()
	test_helpers.UnmountPanic(pDir)
	t.Logf("size=%d, running fsck", fi.Size())
	cmd := exec.Command(test_helpers.GocryptfsBinary, "-fsck", "-mock-kms", cDir)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Start()
	timer := time.AfterFunc(10*time.Second, func() {
		t.Error("timeout, sending SIGINT")
		syscall.Kill(cmd.Process.Pid, syscall.SIGINT)
	})
	code := test_helpers.ExtractCmdExitCode(cmd.Wait())
	timer.Stop()
	if code != 0 {
		t.Errorf("fsck exited %d, want 0", code)
	}
}
