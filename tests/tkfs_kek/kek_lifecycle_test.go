// Package tkfs_kek holds end-to-end integration tests for the TKFS Phase-2 KEK data-key
// lifecycle, driven through the real gocryptfs binary and real FUSE mounts. They use the
// in-process mock gateway (-mock-kms) so no live key service is required.
package tkfs_kek

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/rfjakob/gocryptfs/v2/internal/configfile"
	"github.com/rfjakob/gocryptfs/v2/tests/test_helpers"
)

// TestKEKFullLifecycle exercises the whole KEK data-key lifecycle: -init writes the config and no
// key ring at all; the first mount mints a gateway-wrapped data key, persists only its ciphertext,
// and HKDF-derives the filename + content crypto. A file written through the mount must still be
// readable after an unmount + remount — which can only work if the master key is recovered by
// unwrapping the persisted ciphertext through the gateway, since nothing plaintext is kept on disk
// or across the mount.
func TestKEKFullLifecycle(t *testing.T) {
	cDir := test_helpers.InitFS(t, "-mock-kms")
	os.Chmod(cDir, 0777)
	pDir := cDir + ".mnt"

	test_helpers.MountOrFatal(t, cDir, pDir, "-mock-kms", "-extpass=echo test")
	fn := filepath.Join(pDir, "greeting.txt")
	want := []byte("hello KEK world")
	if err := os.WriteFile(fn, want, 0600); err != nil {
		test_helpers.UnmountPanic(pDir)
		t.Fatalf("write through mount: %v", err)
	}
	test_helpers.UnmountPanic(pDir)

	// Remount forces the key to be re-derived by unwrapping the key-ring ciphertext again.
	test_helpers.MountOrFatal(t, cDir, pDir, "-mock-kms", "-extpass=echo test")
	defer test_helpers.UnmountPanic(pDir)

	got, err := os.ReadFile(fn)
	if err != nil {
		t.Fatalf("read after remount: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("content mismatch after remount: got %q, want %q", got, want)
	}
}

// TestKEKLifecycleViaHarnessDefault proves the test harness's default -mock-kms injection: a plain
// InitFS with no key-source flag must init and mount under the KEK model with no live key service,
// because InitFS now appends -mock-kms and the mock persists the KEK keyed by NodeID so the later
// mount recovers it.
func TestKEKLifecycleViaHarnessDefault(t *testing.T) {
	cDir := test_helpers.InitFS(t) // no -mock-kms passed: relies on the harness injecting it
	os.Chmod(cDir, 0777)
	pDir := cDir + ".mnt"
	test_helpers.MountOrFatal(t, cDir, pDir, "-extpass=echo test")
	defer test_helpers.UnmountPanic(pDir)

	fn := filepath.Join(pDir, "hello.txt")
	want := []byte("harness-injected mock works")
	if err := os.WriteFile(fn, want, 0600); err != nil {
		t.Fatalf("write: %v", err)
	}
	got, err := os.ReadFile(fn)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("content mismatch: got %q, want %q", got, want)
	}
}

// parsedConf is the subset of gocryptfs.conf these tests assert on. Note what is NOT here: the
// config carries no key material at all, since the key ring lives in its own file.
type parsedConf struct {
	Version      uint16
	FeatureFlags []string
	NodeID       string
}

func readConf(t *testing.T, cDir string) parsedConf {
	t.Helper()
	confBytes, err := os.ReadFile(filepath.Join(cDir, "gocryptfs.conf"))
	if err != nil {
		t.Fatal(err)
	}
	var cf parsedConf
	if err := json.Unmarshal(confBytes, &cf); err != nil {
		t.Fatalf("parse config: %v", err)
	}
	// The config must never grow a key field: assert on the raw bytes, not just the struct,
	// since an unknown field would be silently dropped by Unmarshal.
	for _, forbidden := range []string{"KeyRing", "Ciphertext", "Plaintext", "MasterKey", "EncryptedKey"} {
		if bytes.Contains(confBytes, []byte(forbidden)) {
			t.Errorf("gocryptfs.conf contains %q; key material belongs in the key-ring file", forbidden)
		}
	}
	return cf
}

// keyRingPath returns the key-ring file path for a cipherdir.
func keyRingPath(cDir string) string { return filepath.Join(cDir, configfile.KeyRingFileName) }

// readKeyRing loads the key-ring file. absent reports whether the file does not exist, which is
// the state -init leaves behind.
func readKeyRing(t *testing.T, cDir string) (kr parsedKeyRing, absent bool) {
	t.Helper()
	js, err := os.ReadFile(keyRingPath(cDir))
	if os.IsNotExist(err) {
		return kr, true
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(js, &kr); err != nil {
		t.Fatalf("parse key ring: %v", err)
	}
	return kr, false
}

// parsedKeyRing is the subset of the key-ring file these tests assert on.
type parsedKeyRing struct {
	Keys []struct {
		KeyID      string
		Ciphertext []byte
	}
}

// TestKEKFirstMountPersistsOnlyCiphertext asserts the on-disk invariants of the KEK model.
// -init writes a format-v3 config and NO key-ring file — it never contacts the key service. The
// first mount generates the data key and writes exactly one key-ring entry holding only a key id
// and a KEK ciphertext, never a plaintext master key. Neither file has a plaintext-key field at
// all, so the recovered key exists only in memory while mounted.
func TestKEKFirstMountPersistsOnlyCiphertext(t *testing.T) {
	cDir := test_helpers.InitFS(t, "-mock-kms")

	cf := readConf(t, cDir)
	if cf.Version != 3 {
		t.Errorf("config version = %d, want 3 (the KEK hard format break)", cf.Version)
	}
	if cf.NodeID == "" {
		t.Error("config is missing NodeID")
	}
	if _, absent := readKeyRing(t, cDir); !absent {
		t.Fatalf("key-ring file exists after -init, want none (the first mount generates the key)")
	}
	// -init must not even CONTACT the key service: with -mock-kms the first connector use
	// creates the per-NodeID bbolt store (mockGatewayDBPath), so its absence proves no call
	// was made. NodeID is a UUID, which the path sanitizer passes through unchanged.
	mockDB := filepath.Join(os.TempDir(), "tkfs_mock_gateway_"+cf.NodeID+".db")
	if _, err := os.Stat(mockDB); !os.IsNotExist(err) {
		t.Errorf("mock gateway store %q exists right after -init: init contacted the key service", mockDB)
	}

	// First mount: generates the data key and persists its ciphertext in the key-ring file.
	os.Chmod(cDir, 0777)
	pDir := cDir + ".mnt"
	test_helpers.MountOrFatal(t, cDir, pDir, "-mock-kms", "-extpass=echo test")
	// Read the ring while still mounted: the entry must be persisted BEFORE the mount serves
	// I/O (crash safety), not at unmount time.
	kr, absent := readKeyRing(t, cDir)
	test_helpers.UnmountPanic(pDir)
	if absent {
		t.Fatal("no key-ring file after the first mount")
	}
	if len(kr.Keys) != 1 {
		t.Fatalf("key ring has %d entries after the first mount, want exactly 1 (Phase-2 single-key invariant)", len(kr.Keys))
	}
	entry := kr.Keys[0]
	if entry.KeyID == "" {
		t.Error("key-ring entry is missing KeyID")
	}
	if len(entry.Ciphertext) == 0 {
		t.Error("key-ring entry is missing Ciphertext")
	}
	// The config must be untouched by the first mount: it is now static, and only the ring file
	// is rewritten.
	readConf(t, cDir)
	if _, err := os.Stat(mockDB); err != nil {
		t.Errorf("mock gateway store %q missing after the first mount: %v", mockDB, err)
	}

	// A later mount takes the unwrap path and must leave the ring untouched — same single
	// entry, same KeyID, no second generate.
	test_helpers.MountOrFatal(t, cDir, pDir, "-mock-kms", "-extpass=echo test")
	test_helpers.UnmountPanic(pDir)
	kr, _ = readKeyRing(t, cDir)
	if len(kr.Keys) != 1 || kr.Keys[0].KeyID != entry.KeyID {
		t.Errorf("key ring changed on remount: %+v, want the single entry %q", kr.Keys, entry.KeyID)
	}
}

// TestKeyRingFileHiddenFromMount: the key-ring file sits in the cipherdir root next to
// gocryptfs.conf, so like the config it must not show up inside the mount — a readdir of the
// plaintext root would otherwise expose it as an undecryptable name, and tools walking the mount
// would trip on it.
func TestKeyRingFileHiddenFromMount(t *testing.T) {
	cDir := test_helpers.InitFS(t, "-mock-kms")
	os.Chmod(cDir, 0777)
	pDir := cDir + ".mnt"
	test_helpers.MountOrFatal(t, cDir, pDir, "-mock-kms", "-extpass=echo test")
	defer test_helpers.UnmountPanic(pDir)

	// The first mount has created it by now.
	if _, err := os.Stat(keyRingPath(cDir)); err != nil {
		t.Fatalf("key ring missing in cipherdir: %v", err)
	}
	entries, err := os.ReadDir(pDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		if e.Name() == configfile.KeyRingFileName || e.Name() == configfile.ConfDefaultName {
			t.Errorf("%q is visible inside the mount", e.Name())
		}
	}
}

// TestKEKFirstMountFailsClosedWhenPersistFails asserts the data-safety core of the
// first-mount generate: if the ciphertext cannot be persisted, the mount must fail instead of
// serving I/O — anything encrypted under an unpersisted key would be lost forever at unmount.
// An unwritable cipherdir makes the key ring's tmp-file create fail.
func TestKEKFirstMountFailsClosedWhenPersistFails(t *testing.T) {
	cDir := test_helpers.InitFS(t, "-mock-kms")
	pDir := cDir + ".mnt"

	if err := os.Chmod(cDir, 0500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(cDir, 0755)
	if err := test_helpers.Mount(cDir, pDir, false, "-mock-kms", "-extpass=echo test"); err == nil {
		test_helpers.UnmountPanic(pDir)
		t.Fatal("first mount must fail when the key-ring entry cannot be persisted")
	}
	// The failed attempt must leave the filesystem mountable: still no ring, and no stale tmp
	// file blocking the retry.
	if err := os.Chmod(cDir, 0755); err != nil {
		t.Fatal(err)
	}
	test_helpers.MountOrFatal(t, cDir, pDir, "-mock-kms", "-extpass=echo test")
	test_helpers.UnmountPanic(pDir)
}

// TestKEKFirstMountRefusesReadOnly: the first mount must persist the generated key into the
// cipherdir, which "-ro" both forbids in spirit and (on read-only storage) in practice — so
// it fails closed with a clear message instead of silently writing.
func TestKEKFirstMountRefusesReadOnly(t *testing.T) {
	cDir := test_helpers.InitFS(t, "-mock-kms")
	pDir := cDir + ".mnt"

	if err := test_helpers.Mount(cDir, pDir, false, "-ro", "-mock-kms", "-extpass=echo test"); err == nil {
		test_helpers.UnmountPanic(pDir)
		t.Fatal("read-only first mount must be refused (no data key persisted yet)")
	}
	// A writable first mount, then -ro, is the supported order.
	test_helpers.MountOrFatal(t, cDir, pDir, "-mock-kms", "-extpass=echo test")
	test_helpers.UnmountPanic(pDir)
	test_helpers.MountOrFatal(t, cDir, pDir, "-ro", "-mock-kms", "-extpass=echo test")
	test_helpers.UnmountPanic(pDir)
}

// TestKEKRefusesGenerateOverExistingData: a missing key ring is only valid while the cipherdir
// looks exactly as -init left it. If the ring was deleted, or the cipherdir was restored from a
// pre-first-mount backup while already holding files, generating a fresh key would orphan those
// files — the mount must fail closed instead.
func TestKEKRefusesGenerateOverExistingData(t *testing.T) {
	cDir := test_helpers.InitFS(t, "-mock-kms")
	pDir := cDir + ".mnt"

	stray := filepath.Join(cDir, "leftover-ciphertext.bin")
	if err := os.WriteFile(stray, []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := test_helpers.Mount(cDir, pDir, false, "-mock-kms", "-extpass=echo test"); err == nil {
		test_helpers.UnmountPanic(pDir)
		t.Fatal("first mount must refuse to generate a key over a cipherdir with existing data")
	}
	if err := os.Remove(stray); err != nil {
		t.Fatal(err)
	}
	test_helpers.MountOrFatal(t, cDir, pDir, "-mock-kms", "-extpass=echo test")
	test_helpers.UnmountPanic(pDir)
}
