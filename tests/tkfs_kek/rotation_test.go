package tkfs_kek

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/pkg/xattr"

	"github.com/rfjakob/gocryptfs/v2/ctlsock"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// mountWithCtlsock mounts cDir at cDir+".mnt" with a control socket and returns both paths.
func mountWithCtlsock(t *testing.T, cDir string) (pDir, sock string) {
	t.Helper()
	pDir = cDir + ".mnt"
	sock = cDir + ".sock"
	test_helpers.MountOrFatal(t, cDir, pDir, "-ctlsock="+sock, "-mock-kms", "-extpass=echo test")
	// Without this a t.Fatal mid-test leaves a live mount, and test.bash reports "left mounted
	// filesystems behind" on top of the real failure.
	t.Cleanup(func() {
		if stillMounted(pDir) {
			test_helpers.UnmountErr(pDir)
		}
	})
	return pDir, sock
}

// rotate asks the mount to generate a new data key and returns the index it landed on.
func rotate(t *testing.T, sock string) uint16 {
	t.Helper()
	resp := test_helpers.QueryCtlSock(t, sock, ctlsock.RequestStruct{Rotate: true})
	if resp.ErrNo != 0 {
		t.Fatalf("rotate failed: errno %d: %s", resp.ErrNo, resp.ErrText)
	}
	if resp.KeyIdx == 0 {
		t.Fatal("rotate returned index 0, which can only be the initial key")
	}
	return resp.KeyIdx
}

// TestRotateContentAndNames is the end-to-end shape of rotation: everything written before the
// rotation stays readable under the key that wrote it, everything written after uses the new one,
// and a remount — which rebuilds every key from the ring rather than reusing anything in memory —
// still sees both.
func TestRotateContentAndNames(t *testing.T) {
	cDir := test_helpers.InitFS(t, "-mock-kms")
	os.Chmod(cDir, 0777)
	pDir, sock := mountWithCtlsock(t, cDir)

	oldFile := filepath.Join(pDir, "old.txt")
	oldContent := []byte("written under the first key")
	if err := os.WriteFile(oldFile, oldContent, 0600); err != nil {
		test_helpers.UnmountPanic(pDir)
		t.Fatal(err)
	}
	oldDir := filepath.Join(pDir, "olddir")
	if err := os.Mkdir(oldDir, 0700); err != nil {
		test_helpers.UnmountPanic(pDir)
		t.Fatal(err)
	}
	oldDirFile := filepath.Join(oldDir, "inside.txt")
	if err := os.WriteFile(oldDirFile, []byte("in the old directory"), 0600); err != nil {
		test_helpers.UnmountPanic(pDir)
		t.Fatal(err)
	}
	oldLink := filepath.Join(pDir, "old.link")
	if err := os.Symlink("target/of/the/old/key", oldLink); err != nil {
		test_helpers.UnmountPanic(pDir)
		t.Fatal(err)
	}
	oldXattr := []byte("xattr under the first key")
	if err := xattr.LSet(oldFile, "user.rotationtest", oldXattr); err != nil {
		test_helpers.UnmountPanic(pDir)
		t.Fatal(err)
	}

	if idx := rotate(t, sock); idx != 1 {
		test_helpers.UnmountPanic(pDir)
		t.Fatalf("first rotation landed at index %d, want 1", idx)
	}

	// New objects go under the new key.
	newFile := filepath.Join(pDir, "new.txt")
	newContent := []byte("written under the rotated key")
	if err := os.WriteFile(newFile, newContent, 0600); err != nil {
		test_helpers.UnmountPanic(pDir)
		t.Fatal(err)
	}
	newDir := filepath.Join(pDir, "newdir")
	if err := os.Mkdir(newDir, 0700); err != nil {
		test_helpers.UnmountPanic(pDir)
		t.Fatal(err)
	}
	// A file created in the OLD directory after the rotation keeps that directory's name key
	// — rotation is forward-only and never re-keys an existing directory.
	lateFile := filepath.Join(oldDir, "late.txt")
	if err := os.WriteFile(lateFile, []byte("late arrival"), 0600); err != nil {
		test_helpers.UnmountPanic(pDir)
		t.Fatal(err)
	}
	newLink := filepath.Join(pDir, "new.link")
	if err := os.Symlink("target/of/the/new/key", newLink); err != nil {
		test_helpers.UnmountPanic(pDir)
		t.Fatal(err)
	}
	if err := xattr.LSet(newFile, "user.rotationtest", []byte("xattr under the rotated key")); err != nil {
		test_helpers.UnmountPanic(pDir)
		t.Fatal(err)
	}
	test_helpers.UnmountPanic(pDir)

	// The ring must have grown to two entries, both retained.
	kr, absent := readKeyRing(t, cDir)
	if absent || len(kr.Keys) != 2 {
		t.Fatalf("key ring has %d entries after one rotation, want 2", len(kr.Keys))
	}

	// Remount: every key is rebuilt by unwrapping its ring entry.
	test_helpers.MountOrFatal(t, cDir, pDir, "-mock-kms", "-extpass=echo test")
	defer test_helpers.UnmountPanic(pDir)

	for _, tc := range []struct {
		path string
		want []byte
	}{
		{oldFile, oldContent},
		{newFile, newContent},
		{oldDirFile, []byte("in the old directory")},
		{lateFile, []byte("late arrival")},
	} {
		got, err := os.ReadFile(tc.path)
		if err != nil {
			t.Errorf("read %q: %v", tc.path, err)
			continue
		}
		if !bytes.Equal(got, tc.want) {
			t.Errorf("%q = %q, want %q", tc.path, got, tc.want)
		}
	}
	for _, tc := range []struct{ path, want string }{
		{oldLink, "target/of/the/old/key"},
		{newLink, "target/of/the/new/key"},
	} {
		got, err := os.Readlink(tc.path)
		if err != nil {
			t.Errorf("readlink %q: %v", tc.path, err)
			continue
		}
		if got != tc.want {
			t.Errorf("readlink %q = %q, want %q", tc.path, got, tc.want)
		}
	}
	got, err := xattr.LGet(oldFile, "user.rotationtest")
	if err != nil {
		t.Errorf("xattr on the pre-rotation file: %v", err)
	} else if !bytes.Equal(got, oldXattr) {
		t.Errorf("xattr on the pre-rotation file = %q, want %q", got, oldXattr)
	}
	if got, err := xattr.LGet(newFile, "user.rotationtest"); err != nil {
		t.Errorf("xattr on the post-rotation file: %v", err)
	} else if string(got) != "xattr under the rotated key" {
		t.Errorf("xattr on the post-rotation file = %q", got)
	}

	// Both directories must still list, which is the check that each one's names decrypt under
	// the key its own diriv names.
	for _, d := range []string{oldDir, newDir} {
		if _, err := os.ReadDir(d); err != nil {
			t.Errorf("readdir %q: %v", d, err)
		}
	}
	entries, err := os.ReadDir(oldDir)
	if err == nil && len(entries) != 2 {
		t.Errorf("%q has %d entries, want 2", oldDir, len(entries))
	}
}

// An xattr name is a property of the inode, so it must stay addressable when the inode moves into a
// directory that a rotation keyed differently, and when a hard link puts it in two such directories
// at once. Keying xattr names by the containing directory made every one of these silently wrong:
// Getxattr returned ENODATA for an attribute that exists, Removexattr removed nothing, Setxattr
// wrote a second attribute and Listxattr dropped the name as mitigated corruption.
func TestXattrNamesSurviveMoveAcrossRotation(t *testing.T) {
	cDir := test_helpers.InitFS(t, "-mock-kms")
	os.Chmod(cDir, 0777)
	pDir, sock := mountWithCtlsock(t, cDir)
	defer test_helpers.UnmountPanic(pDir)

	// The root directory's index is pinned for the filesystem's life, so a file created here and
	// moved into a post-rotation directory crosses a key boundary.
	rootFile := filepath.Join(pDir, "moved.txt")
	if err := os.WriteFile(rootFile, []byte("payload"), 0600); err != nil {
		t.Fatal(err)
	}
	want := []byte("set before the rotation")
	if err := xattr.LSet(rootFile, "user.moved", want); err != nil {
		t.Fatal(err)
	}

	rotate(t, sock)

	newDir := filepath.Join(pDir, "postrotation")
	if err := os.Mkdir(newDir, 0700); err != nil {
		t.Fatal(err)
	}
	moved := filepath.Join(newDir, "moved.txt")
	if err := os.Rename(rootFile, moved); err != nil {
		t.Fatal(err)
	}

	assertXattr(t, moved, "user.moved", want)

	// A hard link makes the same inode reachable from two differently-keyed directories at once,
	// which is why no location-derived index can work: both paths must see the same attribute.
	linked := filepath.Join(pDir, "linked.txt")
	if err := os.Link(moved, linked); err != nil {
		t.Fatal(err)
	}
	assertXattr(t, linked, "user.moved", want)
	// And a set through one path must be visible through the other rather than creating a second
	// attribute under a different key.
	updated := []byte("set through the link")
	if err := xattr.LSet(linked, "user.moved", updated); err != nil {
		t.Fatal(err)
	}
	assertXattr(t, moved, "user.moved", updated)
	if names, err := xattr.LList(moved); err != nil {
		t.Errorf("list: %v", err)
	} else if n := countXattr(names, "user.moved"); n != 1 {
		t.Errorf("%q appears %d times in %v, want exactly 1", "user.moved", n, names)
	}

	// An attribute set after the move, under the new directory's key, must survive a move back.
	if err := xattr.LSet(moved, "user.later", []byte("set after the rotation")); err != nil {
		t.Fatal(err)
	}
	back := filepath.Join(pDir, "back.txt")
	if err := os.Rename(moved, back); err != nil {
		t.Fatal(err)
	}
	assertXattr(t, back, "user.later", []byte("set after the rotation"))

	// Removal has to find the same stored name the set wrote.
	if err := xattr.LRemove(back, "user.moved"); err != nil {
		t.Errorf("remove: %v", err)
	}
	if _, err := xattr.LGet(back, "user.moved"); err == nil {
		t.Error("the attribute is still readable after Removexattr")
	}
	if names, err := xattr.LList(back); err != nil {
		t.Errorf("list after remove: %v", err)
	} else if countXattr(names, "user.moved") != 0 {
		t.Errorf("%q is still listed after Removexattr: %v", "user.moved", names)
	}
}

// Xattr names follow the inode's key-index marker: an inode whose first encrypted xattr comes after a
// rotation uses the new key, and one that already had xattrs keeps its index.
func TestXattrNamesRotate(t *testing.T) {
	cDir := test_helpers.InitFS(t, "-mock-kms")
	pDir, sock := mountWithCtlsock(t, cDir)
	early := filepath.Join(pDir, "early")
	late := filepath.Join(pDir, "late")
	for _, fn := range []string{early, late} {
		if err := os.WriteFile(fn, nil, 0600); err != nil {
			t.Fatal(err)
		}
	}
	if err := xattr.LSet(early, "user.before", []byte("0")); err != nil {
		t.Fatal(err)
	}
	idx := rotate(t, sock)
	for _, fn := range []string{early, late} {
		if err := xattr.LSet(fn, "user.after", []byte("1")); err != nil {
			t.Fatal(err)
		}
	}

	if got := backingXattrKeyIdx(t, cDir, sock, "early"); got != "0" {
		t.Errorf("early: marker = %s, want 0", got)
	}
	if got, want := backingXattrKeyIdx(t, cDir, sock, "late"), fmt.Sprint(idx); got != want {
		t.Errorf("late: marker = %s, want %s", got, want)
	}
	if names, err := xattr.LList(late); err != nil || !slices.Equal(names, []string{"user.after"}) {
		t.Errorf("list = %v, %v; the marker must not be listed", names, err)
	}

	test_helpers.UnmountPanic(pDir)
	test_helpers.MountOrFatal(t, cDir, pDir, "-mock-kms", "-extpass=echo test")
	defer test_helpers.UnmountPanic(pDir)
	assertXattr(t, early, "user.before", []byte("0"))
	assertXattr(t, early, "user.after", []byte("1"))
	assertXattr(t, late, "user.after", []byte("1"))
}

// An encrypted xattr name with no marker has no index to decrypt under, and must not fall back to one.
func TestXattrNameWithoutMarkerIsRefused(t *testing.T) {
	cDir := test_helpers.InitFS(t, "-mock-kms")
	pDir := cDir + ".mnt"
	sock := cDir + ".sock"
	// The refusal is logged at Warn, which -wpanic would turn into a crash.
	test_helpers.MountOrFatal(t, cDir, pDir, "-ctlsock="+sock, "-mock-kms", "-extpass=echo test", "-wpanic=0")
	defer test_helpers.UnmountPanic(pDir)
	fn := filepath.Join(pDir, "file")
	if err := os.WriteFile(fn, nil, 0600); err != nil {
		t.Fatal(err)
	}
	if err := xattr.LSet(fn, "user.x", []byte("v")); err != nil {
		t.Fatal(err)
	}
	marker := "user.gocryptfs_keyidx." + backingXattrKeyIdx(t, cDir, sock, "file")
	if err := xattr.LRemove(backingPath(t, cDir, sock, "file"), marker); err != nil {
		t.Fatal(err)
	}

	if _, err := xattr.LGet(fn, "user.x"); err == nil {
		t.Error("get succeeded without a marker")
	}
	if names, err := xattr.LList(fn); err != nil || len(names) != 0 {
		t.Errorf("list = %v, %v; want nothing", names, err)
	}
}

// backingPath returns the cipher-side path of "plainPath", relative to the mount root.
func backingPath(t *testing.T, cDir, sock, plainPath string) string {
	t.Helper()
	resp := test_helpers.QueryCtlSock(t, sock, ctlsock.RequestStruct{EncryptPath: plainPath})
	if resp.ErrNo != 0 {
		t.Fatalf("EncryptPath %q: %s", plainPath, resp.ErrText)
	}
	return filepath.Join(cDir, resp.Result)
}

// backingXattrKeyIdx returns the key-index marker on the cipher file behind "plainPath".
func backingXattrKeyIdx(t *testing.T, cDir, sock, plainPath string) string {
	t.Helper()
	names, err := xattr.LList(backingPath(t, cDir, sock, plainPath))
	if err != nil {
		t.Fatal(err)
	}
	var markers []string
	for _, name := range names {
		if s, ok := strings.CutPrefix(name, "user.gocryptfs_keyidx."); ok {
			markers = append(markers, s)
		}
	}
	if len(markers) != 1 {
		t.Fatalf("markers on %q: %v, want exactly one", plainPath, markers)
	}
	return markers[0]
}

// assertXattr checks that "attr" on "path" reads back as "want" and is listed.
func assertXattr(t *testing.T, path, attr string, want []byte) {
	t.Helper()
	got, err := xattr.LGet(path, attr)
	if err != nil {
		t.Errorf("get %q on %q: %v", attr, path, err)
	} else if !bytes.Equal(got, want) {
		t.Errorf("get %q on %q = %q, want %q", attr, path, got, want)
	}
	names, err := xattr.LList(path)
	if err != nil {
		t.Errorf("list %q: %v", path, err)
		return
	}
	if countXattr(names, attr) == 0 {
		t.Errorf("%q is not listed on %q: %v", attr, path, names)
	}
}

func countXattr(names []string, attr string) (n int) {
	for _, name := range names {
		if name == attr {
			n++
		}
	}
	return n
}

// Rotating repeatedly must keep appending, and every retained key must still be usable after a
// remount that unwraps all of them.
func TestRotateRepeatedly(t *testing.T) {
	cDir := test_helpers.InitFS(t, "-mock-kms")
	os.Chmod(cDir, 0777)
	pDir, sock := mountWithCtlsock(t, cDir)

	const rounds = 3
	var files []string
	for i := 0; i <= rounds; i++ {
		fn := filepath.Join(pDir, fmt.Sprintf("gen%d.txt", i))
		if err := os.WriteFile(fn, []byte{byte('a' + i)}, 0600); err != nil {
			test_helpers.UnmountPanic(pDir)
			t.Fatal(err)
		}
		files = append(files, fn)
		if i < rounds {
			if idx := rotate(t, sock); idx != uint16(i+1) {
				test_helpers.UnmountPanic(pDir)
				t.Fatalf("rotation %d landed at index %d", i, idx)
			}
		}
	}
	test_helpers.UnmountPanic(pDir)

	kr, _ := readKeyRing(t, cDir)
	if len(kr.Keys) != rounds+1 {
		t.Fatalf("key ring has %d entries, want %d", len(kr.Keys), rounds+1)
	}
	// One KEK serves the instance for its whole life, so rotation reuses it: every entry names the
	// same KeyID and what differs is the wrapped data key.
	for i, e := range kr.Keys {
		if e.KeyID != kr.Keys[0].KeyID {
			t.Errorf("entry %d names KeyID %q, want the instance's one KEK %q", i, e.KeyID, kr.Keys[0].KeyID)
		}
		for j := 0; j < i; j++ {
			if bytes.Equal(e.Ciphertext, kr.Keys[j].Ciphertext) {
				t.Errorf("entries %d and %d share a Ciphertext; each rotation must wrap a fresh data key", j, i)
			}
		}
	}

	test_helpers.MountOrFatal(t, cDir, pDir, "-mock-kms", "-extpass=echo test")
	defer test_helpers.UnmountPanic(pDir)
	for i, fn := range files {
		got, err := os.ReadFile(fn)
		if err != nil {
			t.Errorf("read %q: %v", fn, err)
			continue
		}
		if len(got) != 1 || got[0] != byte('a'+i) {
			t.Errorf("%q = %q, want %q", fn, got, []byte{byte('a' + i)})
		}
	}
}

// -deterministic-names has to rotate too: it gets an all-zero IV, but the diriv still carries the
// index, so a directory created after a rotation must use the new name key.
func TestRotateDeterministicNames(t *testing.T) {
	cDir := test_helpers.InitFS(t, "-deterministic-names", "-mock-kms")
	os.Chmod(cDir, 0777)
	pDir, sock := mountWithCtlsock(t, cDir)

	// Two directories before the rotation and one after, each holding a child of the same name.
	for _, d := range []string{"before-a", "before-b"} {
		if err := os.MkdirAll(filepath.Join(pDir, d, "child"), 0700); err != nil {
			test_helpers.UnmountPanic(pDir)
			t.Fatal(err)
		}
	}
	rotate(t, sock)
	if err := os.MkdirAll(filepath.Join(pDir, "after", "child"), 0700); err != nil {
		test_helpers.UnmountPanic(pDir)
		t.Fatal(err)
	}
	test_helpers.UnmountPanic(pDir)

	test_helpers.MountOrFatal(t, cDir, pDir, "-mock-kms", "-extpass=echo test")
	defer test_helpers.UnmountPanic(pDir)
	for _, d := range []string{"before-a/child", "before-b/child", "after/child"} {
		if _, err := os.Stat(filepath.Join(pDir, d)); err != nil {
			t.Errorf("stat %q: %v", d, err)
		}
	}
	// Under -deterministic-names the same plaintext name normally encrypts identically
	// everywhere — that is the leak the mode accepts. The two pre-rotation directories are keyed
	// the same and must still agree; the post-rotation one is keyed differently and must not.
	// Without the first half this would also pass if the mode had simply stopped being
	// deterministic.
	names := childNames(t, cDir)
	if len(names) != 3 {
		t.Fatalf("want one child in each of the three backing directories, have %v", names)
	}
	slices.Sort(names)
	var same, differing int
	for i := 1; i < len(names); i++ {
		if names[i] == names[i-1] {
			same++
		} else {
			differing++
		}
	}
	if same != 1 || differing != 1 {
		t.Errorf("child names %v: want exactly two equal (the same-key directories) and one apart", names)
	}
}

// childNames is the encrypted name of the single child in each backing directory, dirivs excluded.
func childNames(t *testing.T, cDir string) []string {
	t.Helper()
	var names []string
	for _, d := range backingDirs(t, cDir, 3) {
		entries, err := os.ReadDir(filepath.Join(cDir, d))
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range entries {
			if e.Name() != nametransform.DirIVFilename {
				names = append(names, e.Name())
			}
		}
	}
	return names
}

// stillMounted reports whether dir is a live mountpoint, so a cleanup does not spend ten retries
// unmounting something a test already unmounted itself.
func stillMounted(dir string) bool {
	mounts, err := os.ReadFile("/proc/self/mounts")
	if err != nil {
		return false
	}
	return bytes.Contains(mounts, []byte(" "+dir+" "))
}

// backingDirs returns the ciphertext names of the directories in the cipherdir root.
func backingDirs(t *testing.T, cDir string, want int) []string {
	t.Helper()
	entries, err := os.ReadDir(cDir)
	if err != nil {
		t.Fatal(err)
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, e.Name())
		}
	}
	if len(dirs) != want {
		t.Fatalf("want %d backing directories in %q, have %v", want, cDir, dirs)
	}
	return dirs
}

// Every mount here lives far under one heartbeat interval, so without the flush in doMount's
// teardown the ring would come back with OpCount 0 and the threshold would bound nothing on
// short-lived mounts. That flush only credits: even a threshold of 1 must not rotate on the way out.
func TestShortMountCreditsItsOps(t *testing.T) {
	cDir := test_helpers.InitFS(t, "-mock-kms")
	os.Chmod(cDir, 0777)
	pDir := cDir + ".mnt"
	test_helpers.MountOrFatal(t, cDir, pDir, "-mock-kms", "-extpass=echo test", "-rotate-op-threshold=1")
	if err := os.WriteFile(filepath.Join(pDir, "f.txt"), []byte("some content"), 0600); err != nil {
		test_helpers.UnmountPanic(pDir)
		t.Fatal(err)
	}
	test_helpers.UnmountPanic(pDir)

	// fusermount returns before the gocryptfs process has run its teardown, and the flush is in
	// there, so poll rather than read once.
	var kr parsedKeyRing
	for range 100 {
		var absent bool
		if kr, absent = readKeyRing(t, cDir); !absent && len(kr.Keys) > 0 && kr.Keys[0].OpCount > 0 {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if len(kr.Keys) != 1 {
		t.Errorf("ring has %d entries, want 1: the teardown flush must never rotate", len(kr.Keys))
	}
	if len(kr.Keys) > 0 && kr.Keys[0].OpCount == 0 {
		t.Error("OpCount = 0; a mount shorter than one interval must still credit what it wrote")
	}
}

// The ring write is outside the kernel's read-only enforcement, so a -ro mount must refuse a rotation
// rather than rewrite KR.
func TestReadOnlyMountRefusesRotate(t *testing.T) {
	cDir := test_helpers.InitFS(t, "-mock-kms")
	pDir := cDir + ".mnt"
	sock := cDir + ".sock"
	// The first mount has to be writable to persist the initial key.
	test_helpers.MountOrFatal(t, cDir, pDir, "-mock-kms", "-extpass=echo test")
	test_helpers.UnmountPanic(pDir)
	before, err := os.ReadFile(filepath.Join(cDir, "KR"))
	if err != nil {
		t.Fatal(err)
	}

	test_helpers.MountOrFatal(t, cDir, pDir, "-ro", "-ctlsock="+sock, "-mock-kms", "-extpass=echo test")
	defer test_helpers.UnmountPanic(pDir)
	resp := test_helpers.QueryCtlSock(t, sock, ctlsock.RequestStruct{Rotate: true})
	if resp.ErrNo == 0 {
		t.Errorf("rotate on a -ro mount succeeded (index %d)", resp.KeyIdx)
	}
	after, err := os.ReadFile(filepath.Join(cDir, "KR"))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Error("a -ro mount rewrote the key ring")
	}
}
