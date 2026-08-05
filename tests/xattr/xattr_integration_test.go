package xattr_tests

// xattr integration tests.
//
// These tests are not integrated into the "matrix" tests because of the need
// to switch TMPDIR to /var/tmp.
// TODO: check if it actually causes trouble in the "matrix" tests.

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/pkg/xattr"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/internal/cryptocore"
	"github.com/rfjakob/gocryptfs/v2/internal/nametransform"
	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

func TestMain(m *testing.M) {
	if !xattrSupported(test_helpers.TmpDir) {
		fmt.Printf("xattrs not supported on %q\n", test_helpers.TmpDir)
		os.Exit(1)
	}
	test_helpers.ResetTmpDir(false)
	test_helpers.InitDefaultCipherDir()
	// Replace the diriv -init wrote with a deterministic one, so encrypted filenames are
	// deterministic.
	os.Remove(test_helpers.DefaultCipherDir + "/gocryptfs.diriv")
	diriv := []byte("1234567890123456")
	err := os.WriteFile(test_helpers.DefaultCipherDir+"/gocryptfs.diriv", diriv, 0400)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	test_helpers.MountOrExit(test_helpers.DefaultCipherDir, test_helpers.DefaultPlainDir)
	r := m.Run()
	test_helpers.UnmountPanic(test_helpers.DefaultPlainDir)
	os.RemoveAll(test_helpers.TmpDir)
	os.Exit(r)
}

func setGetRmList(fn string) error {
	return setGetRmList3(fn, "user.foo", []byte("123456789"))
}

func setGetRmList3(fn string, attr string, val []byte) error {
	// List
	list, err := xattr.LList(fn)
	if err != nil {
		return err
	}
	if len(list) > 0 {
		return fmt.Errorf("Should have gotten empty result, got %v", list)
	}
	err = xattr.LSet(fn, attr, val)
	if err != nil {
		return err
	}
	// Read back
	val2, err := xattr.LGet(fn, attr)
	if err != nil {
		return err
	}
	if !bytes.Equal(val, val2) {
		return fmt.Errorf("wrong readback value: %v != %v", val, val2)
	}
	// Remove
	err = xattr.LRemove(fn, attr)
	if err != nil {
		return err
	}
	// Read back
	val3, err := xattr.LGet(fn, attr)
	if err == nil {
		return fmt.Errorf("attr is still there after deletion!? val3=%v", val3)
	}
	// List
	list, err = xattr.LList(fn)
	if err != nil {
		return err
	}
	if len(list) > 0 {
		return fmt.Errorf("Should have gotten empty result, got %v", list)
	}
	return nil
}

// Test xattr set, get, rm on a regular file.
func TestSetGetRmRegularFile(t *testing.T) {
	fn := test_helpers.DefaultPlainDir + "/TestSetGetRmRegularFile"
	err := os.WriteFile(fn, []byte("12345"), 0700)
	if err != nil {
		t.Fatalf("creating empty file failed: %v", err)
	}
	err = setGetRmList(fn)
	if err != nil {
		t.Error(err)
	}
	fi, _ := os.Lstat(fn)
	if fi.Size() != 5 {
		t.Errorf("file size has changed!? size=%d", fi.Size())
	}
}

// Test xattr set, get, rm on a fifo. This should not hang.
func TestSetGetRmFifo(t *testing.T) {
	fn := test_helpers.DefaultPlainDir + "/TestSetGetRmFifo"
	err := syscall.Mkfifo(fn, 0700)
	if err != nil {
		t.Fatalf("creating fifo failed: %v", err)
	}
	// We expect to get EPERM, but we should not hang:
	// $ setfattr -n user.foo -v XXXXX fifo
	// setfattr: fifo: Operation not permitted
	setGetRmList(fn)
}

// Test xattr set, get, rm on a directory. This should not fail with EISDIR.
func TestSetGetRmDir(t *testing.T) {
	fn := test_helpers.DefaultPlainDir + "/TestSetGetRmDir"
	err := syscall.Mkdir(fn, 0700)
	if err != nil {
		t.Fatalf("creating directory failed: %v", err)
	}
	setGetRmList(fn)
}

func TestXattrSetEmpty(t *testing.T) {
	attr := "user.foo"
	fn := test_helpers.DefaultPlainDir + "/TestXattrSetEmpty1"
	err := os.WriteFile(fn, nil, 0700)
	if err != nil {
		t.Fatalf("creating empty file failed: %v", err)
	}
	// Make sure it does not exist already
	_, err = xattr.LGet(fn, attr)
	if err == nil {
		t.Fatal("we should have got an error here")
	}
	// Set empty value
	err = xattr.LSet(fn, attr, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Read back
	val, err := xattr.LGet(fn, attr)
	if err != nil {
		t.Fatal(err)
	}
	if len(val) != 0 {
		t.Errorf("wrong length: want=0 have=%d", len(val))
	}
	// Overwrite empty value with something
	val1 := []byte("xyz123")
	err = xattr.LSet(fn, attr, val1)
	if err != nil {
		t.Fatal(err)
	}
	// Read back
	val2, err := xattr.LGet(fn, attr)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(val1, val2) {
		t.Fatalf("wrong readback value: %v != %v", val1, val2)
	}
	// Overwrite something with empty value
	err = xattr.LSet(fn, attr, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Read back
	val, err = xattr.LGet(fn, attr)
	if err != nil {
		t.Fatal(err)
	}
	if len(val) != 0 {
		t.Errorf("wrong length: want=0 have=%d", len(val2))
	}
}

func TestXattrList(t *testing.T) {
	fn := test_helpers.DefaultPlainDir + "/TestXattrList"
	err := os.WriteFile(fn, nil, 0700)
	if err != nil {
		t.Fatalf("creating empty file failed: %v", err)
	}
	val := []byte("xxxxxxxxyyyyyyyyyyyyyyyzzzzzzzzzzzzz")
	num := 20
	for i := 1; i <= num; i++ {
		attr := fmt.Sprintf("user.TestXattrList.%02d", i)
		err = xattr.LSet(fn, attr, val)
		if err != nil {
			t.Fatal(err)
		}
	}
	names, err := xattr.LList(fn)
	if err != nil {
		t.Fatal(err)
	}
	if len(names) != num {
		t.Errorf("wrong number of names, want=%d have=%d", num, len(names))
	}
	for _, n := range names {
		if !strings.HasPrefix(n, "user.TestXattrList.") {
			t.Errorf("unexpected attr name: %q", n)
		}
	}
}

func xattrSupported(path string) bool {
	_, err := xattr.LGet(path, "user.xattrSupported-dummy-value")
	if err == nil {
		return true
	}
	err2 := err.(*xattr.Error)
	return err2.Err != syscall.EOPNOTSUPP
}

// lsCipherdir lists the encrypted entries of a cipherdir directory, skipping filesystem
// metadata.
func lsCipherdir(t *testing.T, dir string) map[string]bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	out := make(map[string]bool)
	for _, e := range entries {
		switch e.Name() {
		case nametransform.DirIVFilename, configfile.ConfDefaultName, configfile.KeyRingFileName:
			continue
		}
		out[e.Name()] = true
	}
	return out
}

// findNewCiphertextName returns the single entry "dir" gained since the "before" snapshot. The
// encrypted name cannot be hard-coded: it depends on the EME filename key, which is HKDF-derived
// from the gateway-issued master key and so differs per filesystem. Diffing against a snapshot
// works regardless of what earlier tests left in the directory.
func findNewCiphertextName(t *testing.T, dir string, before map[string]bool) string {
	t.Helper()
	var found []string
	for name := range lsCipherdir(t, dir) {
		if !before[name] {
			found = append(found, name)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one new ciphertext entry in %q, have %v", dir, found)
	}
	return filepath.Join(dir, found[0])
}

// findEncryptedXattrName returns the single "user.gocryptfs.*" xattr name on the backing file.
// Like the filename, the encrypted xattr name depends on the EME key and cannot be hard-coded.
func findEncryptedXattrName(t *testing.T, cPath string) string {
	t.Helper()
	names, err := xattr.LList(cPath)
	if err != nil {
		t.Fatal(err)
	}
	var found []string
	for _, n := range names {
		if strings.HasPrefix(n, "user.gocryptfs.") {
			found = append(found, n)
		}
	}
	if len(found) != 1 {
		t.Fatalf("want exactly one encrypted xattr on %q, have %v", cPath, found)
	}
	return found[0]
}

func TestBase64XattrRead(t *testing.T) {
	attrName := "user.test"
	attrName2 := "user.test2"
	attrValue := fmt.Sprintf("test.%d", cryptocore.RandUint64())

	// Own subdirectory, so the file's backing ciphertext is the only entry in it.
	beforeRoot := lsCipherdir(t, test_helpers.DefaultCipherDir)
	pSubdir := test_helpers.DefaultPlainDir + "/TestBase64XattrDir"
	if err := os.Mkdir(pSubdir, 0700); err != nil {
		t.Fatal(err)
	}
	cSubdir := findNewCiphertextName(t, test_helpers.DefaultCipherDir, beforeRoot)

	plainFn := pSubdir + "/TestBase64Xattr"
	err := os.WriteFile(plainFn, nil, 0700)
	if err != nil {
		t.Fatalf("creating empty file failed: %v", err)
	}
	encryptedFn := findNewCiphertextName(t, cSubdir, nil)

	xattr.LSet(plainFn, attrName, []byte(attrValue))
	encryptedAttrName := findEncryptedXattrName(t, encryptedFn)

	encryptedAttrValue, err1 := xattr.LGet(encryptedFn, encryptedAttrName)
	if err1 != nil {
		t.Fatal(err1)
	}

	// The name for attrName2, obtained the same way: set it through the mount, then read back
	// the name that appeared on the backing file.
	xattr.LSet(plainFn, attrName2, []byte("placeholder"))
	var encryptedAttrName2 string
	names, err := xattr.LList(encryptedFn)
	if err != nil {
		t.Fatal(err)
	}
	for _, n := range names {
		if strings.HasPrefix(n, "user.gocryptfs.") && n != encryptedAttrName {
			encryptedAttrName2 = n
		}
	}
	if encryptedAttrName2 == "" {
		t.Fatalf("could not find the encrypted name for %q in %v", attrName2, names)
	}

	xattr.LSet(encryptedFn, encryptedAttrName2, encryptedAttrValue)
	plainValue, err := xattr.LGet(plainFn, attrName2)

	if err != nil || string(plainValue) != attrValue {
		t.Fatalf("Attribute binary value decryption error: have=%q want=%q err=%v", string(plainValue), attrValue, err)
	}

	encryptedAttrValue64 := base64.RawURLEncoding.EncodeToString(encryptedAttrValue)
	xattr.LSet(encryptedFn, encryptedAttrName2, []byte(encryptedAttrValue64))

	plainValue, err = xattr.LGet(plainFn, attrName2)
	if err != nil || string(plainValue) != attrValue {
		t.Fatalf("Attribute base64-encoded value decryption error %s != %s %v", string(plainValue), attrValue, err)
	}

	// Remount with -wpanic=false so gocryptfs does not panics when it sees
	// the broken xattrs
	test_helpers.UnmountPanic(test_helpers.DefaultPlainDir)
	test_helpers.MountOrExit(test_helpers.DefaultCipherDir, test_helpers.DefaultPlainDir, "-wpanic=false")

	brokenVals := []string{
		"111",
		"raw-test-long-block123",
		"raw-test-long-block123-xyz11111111111111111111111111111111111111",
		"$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$$",
	}
	for _, val := range brokenVals {
		xattr.LSet(encryptedFn, encryptedAttrName2, []byte(val))
		plainValue, err = xattr.LGet(plainFn, attrName2)
		err2, _ := err.(*xattr.Error)
		if err == nil || err2.Err != syscall.EIO {
			t.Fatalf("Incorrect handling of broken data %s %v", string(plainValue), err)
		}
	}
}

// Listing xattrs should work even when we don't have read access
func TestList0000File(t *testing.T) {
	fn := test_helpers.DefaultPlainDir + "/TestList0000File"
	err := os.WriteFile(fn, nil, 0000)
	if err != nil {
		t.Fatalf("creating empty file failed: %v", err)
	}
	_, err = xattr.LList(fn)
	if err != nil {
		t.Error(err)
	}
}

// Setting xattrs should work even when we don't have read access
func TestSet0200File(t *testing.T) {
	fn := test_helpers.DefaultPlainDir + "/TestSet0200File"
	err := os.WriteFile(fn, nil, 0200)
	if err != nil {
		t.Fatalf("creating empty file failed: %v", err)
	}
	err = xattr.LSet(fn, "user.foo", []byte("bar"))
	if err != nil {
		t.Error(err)
	}
}

// Listing xattrs should work even when we don't have read access
func TestList0000Dir(t *testing.T) {
	fn := test_helpers.DefaultPlainDir + "/TestList0000Dir"
	err := syscall.Mkdir(fn, 0000)
	if err != nil {
		t.Fatalf("creating directory failed: %v", err)
	}
	_, err = xattr.LList(fn)
	os.Chmod(fn, 0700)
	if err != nil {
		t.Error(err)
	}
}

// Setting xattrs should work even when we don't have read access
func TestSet0200Dir(t *testing.T) {
	fn := test_helpers.DefaultPlainDir + "/TestSet0200Dir"
	err := syscall.Mkdir(fn, 0200)
	if err != nil {
		t.Fatalf("creating directory failed: %v", err)
	}
	err = xattr.LSet(fn, "user.foo", []byte("bar"))
	os.Chmod(fn, 0700)
	if err != nil {
		t.Error(err)
	}
}

func TestAcl(t *testing.T) {
	fn := test_helpers.DefaultPlainDir + "/TestAcl"
	err := os.WriteFile(fn, nil, 0600)
	if err != nil {
		t.Fatalf("creating empty file failed: %v", err)
	}
	// ACLs are blobs generated in userspace, let's steal a valid ACL from
	// setfacl:
	//
	// $ setfacl -m u:root:r file
	// $ getfattr -n system.posix_acl_access file
	// # file: file
	// system.posix_acl_access=0sAgAAAAEABgD/////AgAEAAAAAAAEAAQA/////xAABAD/////IAAEAP////8=
	//
	// The ACL gives user root additional read rights, in other words, it should
	// have no effect at all.

	acl, err := base64.StdEncoding.DecodeString("AgAAAAEABgD/////AgAEAAAAAAAEAAQA/////xAABAD/////IAAEAP////8=")
	if err != nil {
		t.Fatal(err)
	}
	if len(acl) != 44 {
		t.Fatal(len(acl))
	}
	err = setGetRmList3(fn, "system.posix_acl_access", acl)
	if err != nil {
		t.Error(err)
	}
}

// TestSlashInName checks that slashes in xattr names are allowed
// https://github.com/rfjakob/gocryptfs/issues/627
func TestSlashInName(t *testing.T) {
	fn := test_helpers.DefaultPlainDir + "/" + t.Name()
	err := os.WriteFile(fn, []byte("12345"), 0700)
	if err != nil {
		t.Fatalf("creating empty file failed: %v", err)
	}
	err = setGetRmList3(fn, "user.foo@https://bar", []byte("val"))
	if err != nil {
		t.Error(err)
	}
}
