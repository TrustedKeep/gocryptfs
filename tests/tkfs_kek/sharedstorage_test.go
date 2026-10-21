package tkfs_kek

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/rfjakob/gocryptfs/v2/ctlsock"
	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// mountShared mounts cDir at pDir with -sharedstorage, its own control socket and its own NodeID.
func mountShared(t *testing.T, cDir, pDir, sock string) {
	t.Helper()
	test_helpers.MountOrFatal(t, cDir, pDir, "-sharedstorage", "-ctlsock="+sock, "-node-id="+filepath.Base(pDir),
		"-mock-kms", "-extpass=echo test")
	t.Cleanup(func() {
		if stillMounted(pDir) {
			test_helpers.UnmountErr(pDir)
		}
	})
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}

func assertContent(t *testing.T, path, want string) {
	t.Helper()
	if got, err := os.ReadFile(path); err != nil {
		t.Errorf("read %q: %v", path, err)
	} else if string(got) != want {
		t.Errorf("%q = %q, want %q", path, got, want)
	}
}

func assertListing(t *testing.T, dir string, want ...string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Errorf("readdir %q: %v", dir, err)
		return
	}
	var got []string
	for _, e := range entries {
		got = append(got, e.Name())
	}
	if !slices.Equal(got, want) {
		t.Errorf("%q lists %v, want %v", dir, got, want)
	}
}

// A rotation on one mount is learned by the other on first contact: through a file header for
// content, through a diriv for names, and from then on the peer writes under the new key too.
func TestSharedRotationSeenByPeer(t *testing.T) {
	cDir := test_helpers.InitFS(t, "-mock-kms")
	pA, sockA := cDir+".a", cDir+".a.sock"
	pB, sockB := cDir+".b", cDir+".b.sock"
	mountShared(t, cDir, pA, sockA)
	mountShared(t, cDir, pB, sockB)

	if idx := rotate(t, sockA); idx != 1 {
		t.Fatalf("rotation landed at index %d, want 1", idx)
	}
	writeFile(t, filepath.Join(pA, "file"), "from A")
	assertContent(t, filepath.Join(pB, "file"), "from A")
	f, err := os.OpenFile(filepath.Join(pB, "file"), os.O_WRONLY|os.O_APPEND, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.WriteString(", then B"); err != nil {
		t.Error(err)
	}
	if err := f.Close(); err != nil {
		t.Error(err)
	}
	assertContent(t, filepath.Join(pA, "file"), "from A, then B")
	assertContent(t, filepath.Join(pB, "file"), "from A, then B")
	if got := headerKeyIdx(t, backingPath(t, cDir, sockA, "file")); got != 1 {
		t.Errorf("file header: index %d, want 1", got)
	}

	if idx := rotate(t, sockA); idx != 2 {
		t.Fatalf("second rotation landed at index %d, want 2", idx)
	}
	dirA, dirB := filepath.Join(pA, "dir"), filepath.Join(pB, "dir")
	if err := os.Mkdir(dirA, 0700); err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dirA, "a"), "a")
	assertListing(t, dirB, "a")
	writeFile(t, filepath.Join(dirB, "b"), "b")
	assertListing(t, dirA, "a", "b")
	assertContent(t, filepath.Join(dirA, "b"), "b")
	if got := headerKeyIdx(t, backingPath(t, cDir, sockB, "dir/b")); got != 2 {
		t.Errorf("B's file header: index %d, want 2, the key B learned", got)
	}

	for _, sock := range []string{sockA, sockB} {
		if resp := test_helpers.QueryCtlSock(t, sock, ctlsock.RequestStruct{Status: true}); len(resp.KeyHoles) != 0 {
			t.Errorf("%s: KeyHoles = %v, want none", sock, resp.KeyHoles)
		}
	}
	if kr, _ := readKeyRing(t, cDir); len(kr.Keys) != 3 {
		t.Errorf("ring has %d entries, want 3", len(kr.Keys))
	}
}

// bgMount is a mount process started without waiting for it to serve.
type bgMount struct {
	pDir string
	cmd  *exec.Cmd
	out  bytes.Buffer
	done chan struct{}
	err  error
}

// startShared starts a -sharedstorage mount and returns at once, so two can race. test_helpers.Mount
// cannot do that: it waits for a process-wide signal and records the mount in an unguarded map.
func startShared(t *testing.T, cDir, pDir string) *bgMount {
	t.Helper()
	if err := os.Mkdir(pDir, 0700); err != nil {
		t.Fatal(err)
	}
	m := &bgMount{pDir: pDir, done: make(chan struct{})}
	m.cmd = exec.Command(test_helpers.GocryptfsBinary, "-wpanic", "-nosyslog", "-fg", "-health-check-port=-1",
		"-sharedstorage", "-node-id="+filepath.Base(pDir), "-mock-kms", "-extpass=echo test", cDir, pDir)
	m.cmd.Stdout, m.cmd.Stderr = &m.out, &m.out
	if err := m.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	go func() {
		m.err = m.cmd.Wait()
		close(m.done)
	}()
	t.Cleanup(func() {
		if stillMounted(pDir) {
			exec.Command(test_helpers.UnmountScript, "-u", pDir).Run()
		}
		select {
		case <-m.done:
		case <-time.After(10 * time.Second):
			m.cmd.Process.Kill()
		}
	})
	return m
}

func (m *bgMount) waitMounted(t *testing.T) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		select {
		case <-m.done:
			t.Fatalf("mount at %q exited: %v\n%s", m.pDir, m.err, m.out.String())
		default:
		}
		if stillMounted(m.pDir) {
			return
		}
	}
	t.Fatalf("mount at %q did not come up within 5s", m.pDir)
}

func (m *bgMount) stop(t *testing.T) {
	t.Helper()
	var err error
	for range 10 {
		if err = exec.Command(test_helpers.UnmountScript, "-u", m.pDir).Run(); err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("unmount %q: %v", m.pDir, err)
	}
	select {
	case <-m.done:
	case <-time.After(10 * time.Second):
		t.Fatalf("mount at %q did not exit after unmount", m.pDir)
	}
	if m.err != nil {
		t.Errorf("mount at %q exited with %v\n%s", m.pDir, m.err, m.out.String())
	}
}

// holdMockStore blocks every key-service call of cDir's mounts until release runs, so mounts started
// while it is held reach the key ring together.
func holdMockStore(t *testing.T, cDir string) (release func()) {
	t.Helper()
	path := filepath.Join(os.TempDir(), "tkfs_mock_gateway_"+readConf(t, cDir).NodeID+".db")
	f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE, 0600)
	if err != nil {
		t.Fatal(err)
	}
	if err := syscall.Flock(int(f.Fd()), syscall.LOCK_EX); err != nil {
		t.Fatal(err)
	}
	return func() { f.Close() }
}

// Two first mounts racing on a fresh cipherdir must converge on one entry 0 and one root diriv, so
// each sees the other's files and a later mount reads them all.
func TestSharedFirstMountsRace(t *testing.T) {
	const rounds = 10
	var raced int
	for range rounds {
		cDir := test_helpers.InitFS(t, "-mock-kms")
		pA, pB := cDir+".a", cDir+".b"
		release := holdMockStore(t, cDir)
		a, b := startShared(t, cDir, pA), startShared(t, cDir, pB)
		// Well inside the mock's 2 s wait for its store.
		time.Sleep(200 * time.Millisecond)
		release()
		a.waitMounted(t)
		b.waitMounted(t)

		if kr, _ := readKeyRing(t, cDir); len(kr.Keys) != 1 {
			t.Errorf("ring has %d entries after two first mounts, want 1", len(kr.Keys))
		}
		root, err := os.ReadDir(cDir)
		if err != nil {
			t.Fatal(err)
		}
		var names []string
		for _, e := range root {
			names = append(names, e.Name())
		}
		if want := []string{configfile.KeyRingFileName, configfile.ConfDefaultName, nametransform.DirIVFilename}; !slices.Equal(names, want) {
			t.Errorf("cipherdir root = %v, want %v", names, want)
		}
		dirIV, err := os.ReadFile(filepath.Join(cDir, nametransform.DirIVFilename))
		if err != nil {
			t.Fatal(err)
		}
		if _, idx, err := nametransform.CheckDirIVRecord(dirIV, false); err != nil || idx != 0 {
			t.Errorf("root diriv: index %d, %v", idx, err)
		}
		ring, err := os.ReadDir(configfile.KeyRingDir(cDir))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range ring {
			if strings.HasPrefix(e.Name(), ".tmp.") {
				t.Errorf("staging file %q left in the ring", e.Name())
			}
		}

		writeFile(t, filepath.Join(pA, "a"), "from A")
		writeFile(t, filepath.Join(pB, "b"), "from B")
		for _, p := range []string{pA, pB} {
			assertListing(t, p, "a", "b")
			assertContent(t, filepath.Join(p, "a"), "from A")
			assertContent(t, filepath.Join(p, "b"), "from B")
		}
		a.stop(t)
		b.stop(t)
		for _, m := range []*bgMount{a, b} {
			if strings.Contains(m.out.String(), "Another mount initialized this filesystem first") {
				raced++
			}
		}

		test_helpers.MountOrFatal(t, cDir, pA, "-mock-kms", "-extpass=echo test")
		assertContent(t, filepath.Join(pA, "a"), "from A")
		assertContent(t, filepath.Join(pA, "b"), "from B")
		test_helpers.UnmountPanic(pA)
	}
	t.Logf("a first mount lost the race for entry 0 in %d of %d rounds", raced, rounds)
}

// Shared mounts coexist only with each other: a mount without -sharedstorage is refused next to a
// shared one, and a shared one next to it.
func TestSharedAndExclusiveMountsExclude(t *testing.T) {
	cDir := test_helpers.InitFS(t, "-mock-kms")
	pA, pB := cDir+".a", cDir+".b"
	for _, c := range []struct {
		name          string
		first, second []string
	}{
		{"exclusive next to shared", []string{"-sharedstorage"}, nil},
		{"shared next to exclusive", nil, []string{"-sharedstorage"}},
	} {
		test_helpers.MountOrFatal(t, cDir, pA, append(c.first, "-mock-kms", "-extpass=echo test")...)
		err := test_helpers.Mount(cDir, pB, false, append(c.second, "-mock-kms", "-extpass=echo test")...)
		if err == nil {
			test_helpers.UnmountPanic(pB)
			t.Errorf("%s: the mount was not refused", c.name)
		} else if code := test_helpers.ExtractCmdExitCode(err); code != exitcodes.AlreadyMounted {
			t.Errorf("%s: exit code = %d, want %d", c.name, code, exitcodes.AlreadyMounted)
		}
		test_helpers.UnmountPanic(pA)
	}
}

// Two shared mounts cannot report as one: a second mount using a live mount's NodeID, given or the
// config's, is refused, and the NodeID is free again once that mount is gone.
func TestSharedDuplicateNodeIDRefused(t *testing.T) {
	for _, nodeID := range [][]string{{"-node-id=same"}, nil} {
		cDir := test_helpers.InitFS(t, "-mock-kms")
		pA, pB := cDir+".a", cDir+".b"
		args := append([]string{"-sharedstorage", "-mock-kms", "-extpass=echo test"}, nodeID...)
		test_helpers.MountOrFatal(t, cDir, pA, args...)
		err := test_helpers.Mount(cDir, pB, false, args...)
		if err == nil {
			test_helpers.UnmountPanic(pB)
			t.Errorf("%v: a second mount with the same NodeID was not refused", nodeID)
		} else if code := test_helpers.ExtractCmdExitCode(err); code != exitcodes.AlreadyMounted {
			t.Errorf("%v: exit code = %d, want %d", nodeID, code, exitcodes.AlreadyMounted)
		}
		test_helpers.UnmountPanic(pA)
		test_helpers.MountOrFatal(t, cDir, pB, args...)
		test_helpers.UnmountPanic(pB)
	}
}

// Unmount returns only once the process is gone, so nothing writes the cipherdir after it and it can
// be removed at once. Each mount's final flush writes into KR/ops, which made removal racy before.
func TestSharedUnmountReleasesCipherdir(t *testing.T) {
	for range 3 {
		cDir := test_helpers.InitFS(t, "-mock-kms")
		pA, pB := cDir+".a", cDir+".b"
		mountShared(t, cDir, pA, cDir+".a.sock")
		mountShared(t, cDir, pB, cDir+".b.sock")
		writeFile(t, filepath.Join(pA, "a"), "from A")
		writeFile(t, filepath.Join(pB, "b"), "from B")
		for _, p := range []string{pA, pB} {
			test_helpers.UnmountPanic(p)
			select {
			case <-test_helpers.MountInfo[p].Exited:
			default:
				t.Errorf("the process behind %q still runs after its unmount returned", p)
			}
		}
		if err := os.RemoveAll(cDir); err != nil {
			t.Fatalf("removing the cipherdir right after unmount: %v", err)
		}
		if _, err := os.Stat(cDir); !os.IsNotExist(err) {
			t.Errorf("cipherdir still exists after RemoveAll: %v", err)
		}
	}
}
