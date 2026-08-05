package cli

import (
	"fmt"
	"net"
	"net/http"
	"syscall"
	"testing"
	"time"

	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// freePort returns a port that was free a moment ago. Inherently racy — something else can take it
// before the mount binds — but nothing else on the machine is handing out ports to this test, and
// the alternative (a fixed port) collides with whatever else is listening.
func freePort(t *testing.T) int {
	t.Helper()
	ln, err := net.Listen("tcp", ":0")
	if err != nil {
		t.Fatal(err)
	}
	port := ln.Addr().(*net.TCPAddr).Port
	ln.Close()
	return port
}

// A mount must actually answer on the health-check port once it signals ready. Mount() returns
// after the ready signal, so there is no sleep here: if the endpoint needed one, the ordering
// between binding the listener and signalling ready would be wrong.
func TestHealthCheckServes(t *testing.T) {
	cDir := test_helpers.InitFS(t)
	pDir := cDir + ".mnt"
	port := freePort(t)
	test_helpers.MountOrFatal(t, cDir, pDir, "-extpass=echo test", fmt.Sprintf("-health-check-port=%d", port))
	defer test_helpers.UnmountPanic(pDir)

	c := &http.Client{Timeout: 5 * time.Second}
	resp, err := c.Get(fmt.Sprintf("http://127.0.0.1:%d/", port))
	if err != nil {
		t.Fatalf("health check should answer once the mount is ready: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusOK)
	}
}

// A health-check port that cannot be bound is fatal: a mount nobody can probe is invisible to its
// supervisor, and the usual cause is a second mount colliding with the first. The mountpoint must
// come back clean, which is what binding before the FUSE mount buys — the old code bound after and
// would have left a mount attached with no process behind it.
func TestHealthCheckPortBusyIsFatal(t *testing.T) {
	cDir := test_helpers.InitFS(t)
	pDir := cDir + ".mnt"
	port := freePort(t)
	// The wildcard address, matching what the mount binds. A 127.0.0.1-only squatter is not a
	// conflict for a wildcard bind once SO_REUSEADDR is in play (Go sets it), and the mount would
	// come up alongside it.
	squatter, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer squatter.Close()

	err = test_helpers.Mount(cDir, pDir, false, "-extpass=echo test", fmt.Sprintf("-health-check-port=%d", port))
	if err == nil {
		test_helpers.UnmountPanic(pDir)
		t.Fatal("mount should have failed: the health-check port is taken")
	}
	if code := test_helpers.ExtractCmdExitCode(err); code != exitcodes.HealthCheck {
		t.Errorf("exit code = %d, want %d", code, exitcodes.HealthCheck)
	}
	if isMounted(t, pDir) {
		t.Error("mountpoint is still mounted after a fatal bind failure")
	}
}

// isMounted reports whether anything is mounted at "path", via the FUSE superblock magic: a
// mountpoint that is still attached statfs's as fuse, a plain directory does not.
func isMounted(t *testing.T, path string) bool {
	t.Helper()
	const fuseSuperMagic = 0x65735546
	var st syscall.Statfs_t
	if err := syscall.Statfs(path, &st); err != nil {
		// ENOTCONN is a mountpoint whose server died - still attached.
		return err == syscall.ENOTCONN
	}
	return uint32(st.Type) == fuseSuperMagic
}

// A negative port means "not supervised": the mount must come up with no listener at all. This is
// the path the whole test suite runs on. (0 does NOT disable — it means unset, so it would bind the
// default port and collide with every other package running in parallel.)
func TestHealthCheckDisabled(t *testing.T) {
	cDir := test_helpers.InitFS(t)
	pDir := cDir + ".mnt"
	test_helpers.MountOrFatal(t, cDir, pDir, "-extpass=echo test", "-health-check-port=-1")
	defer test_helpers.UnmountPanic(pDir)
	// The mount is up and serving, which is the assertion. Nothing to probe by design.
	test_helpers.TestMkdirRmdir(t, pDir)
}
