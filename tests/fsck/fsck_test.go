package fsck

import (
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// TestTerabyteFile verifies that fsck does something intelligent when it hits
// a 1-terabyte sparse file (trying to read the whole file is not intelligent).
func TestTerabyteFile(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skipf("Only linux supports SEEK_DATA")
	}
	cDir := test_helpers.InitFS(t)
	pDir := cDir + ".mnt"
	test_helpers.MountOrFatal(t, cDir, pDir, "-extpass", "echo test")
	defer test_helpers.UnmountErr(pDir)
	veryBigFile := pDir + "/veryBigFile"
	fd, err := os.Create(veryBigFile)
	if err != nil {
		t.Fatal(err)
	}
	defer fd.Close()
	var oneTiB int64 = 1024 * 1024 * 1024 * 1024
	_, err = fd.WriteAt([]byte("foobar"), oneTiB)
	if err != nil {
		t.Fatal(err)
	}
	fi, err := fd.Stat()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("size=%d, running fsck", fi.Size())
	cmd := exec.Command(test_helpers.GocryptfsBinary, "-fsck", "-extpass", "echo test", cDir)
	cmd.Stderr = os.Stderr
	cmd.Stdout = os.Stdout
	cmd.Start()
	timer := time.AfterFunc(10*time.Second, func() {
		t.Error("timeout, sending SIGINT")
		syscall.Kill(cmd.Process.Pid, syscall.SIGINT)
	})
	cmd.Wait()
	timer.Stop()
}
