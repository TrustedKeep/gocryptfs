package configfile

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/rfjakob/gocryptfs/v2/internal/contentenc"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
)

func testEntry(keyID string, b byte) KeyRingEntry {
	return KeyRingEntry{KeyID: keyID, Ciphertext: []byte{b, b + 1}, CreatedAt: time.Unix(1000+int64(b), 0).UTC()}
}

// ringCipherdir is a cipherdir whose ring directories exist, as a writable mount leaves them.
func ringCipherdir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := CreateKeyRingDir(dir); err != nil {
		t.Fatal(err)
	}
	return dir
}

func writeRingFile(t *testing.T, cipherdir, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(KeyRingDir(cipherdir), name), data, 0400); err != nil {
		t.Fatal(err)
	}
}

func writeEntry(t *testing.T, cipherdir string, idx uint16, e KeyRingEntry) {
	t.Helper()
	js, err := json.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	writeRingFile(t, cipherdir, fmt.Sprintf("%05d", idx), js)
}

func wantCode(t *testing.T, err error, code int) {
	t.Helper()
	var coded exitcodes.Err
	if !errors.As(err, &coded) || coded.Code() != code {
		t.Errorf("error = %v (%T), want one carrying exit code %d", err, err, code)
	}
}

// ringNames lists KR/, which after any publish must hold no staging file.
func ringNames(t *testing.T, cipherdir string) []string {
	t.Helper()
	names, err := readDirNames(KeyRingDir(cipherdir))
	if err != nil {
		t.Fatal(err)
	}
	slices.Sort(names)
	return names
}

func wantNoStaging(t *testing.T, cipherdir string) {
	t.Helper()
	for _, n := range ringNames(t, cipherdir) {
		if strings.HasPrefix(n, keyRingTmpPrefix) {
			t.Errorf("staging file %q left behind", n)
		}
	}
}

// Active is the newest entry, and an empty ring has none.
func TestActive(t *testing.T) {
	kr := &KeyRing{}
	if _, err := kr.Active(); err == nil {
		t.Error("empty ring must be rejected")
	}
	if _, err := kr.ActiveIdx(); err == nil {
		t.Error("empty ring must have no active index")
	}
	kr.Keys = []KeyRingEntry{testEntry("k1", 1), testEntry("k1", 3)}
	e, err := kr.Active()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(e.Ciphertext, []byte{3, 4}) {
		t.Errorf("Ciphertext = %v, want the newest entry's {3 4}", e.Ciphertext)
	}
	if got, err := kr.ActiveIdx(); err != nil || got != 1 {
		t.Errorf("ActiveIdx = %d, %v, want 1, nil", got, err)
	}
}

// Every present entry needs a Ciphertext and a CreatedAt, a ring names one KEK, and a hole is allowed
// anywhere but the head.
func TestKeyRingValidate(t *testing.T) {
	good := testEntry("kek-1", 1)
	cases := []struct {
		name string
		keys []KeyRingEntry
		ok   bool
	}{
		{"empty", nil, true},
		{"one KEK", []KeyRingEntry{good, testEntry("kek-1", 2)}, true},
		{"hole below the head", []KeyRingEntry{{}, good, {}, good}, true},
		{"head missing", []KeyRingEntry{good, {}}, false},
		{"only entry missing", []KeyRingEntry{{}}, false},
		{"no Ciphertext", []KeyRingEntry{{KeyID: "kek-1", CreatedAt: good.CreatedAt}}, false},
		{"no CreatedAt", []KeyRingEntry{{KeyID: "kek-1", Ciphertext: []byte{1}}}, false},
		{"two KEKs", []KeyRingEntry{good, testEntry("kek-2", 2)}, false},
		{"two KEKs across a hole", []KeyRingEntry{good, {}, testEntry("kek-2", 2)}, false},
	}
	for _, c := range cases {
		err := (&KeyRing{Keys: c.keys}).Validate()
		if (err == nil) != c.ok {
			t.Errorf("%s: Validate = %v, want ok=%v", c.name, err, c.ok)
		}
	}
}

// A ring index is a uint16, so a ring holds at most 1<<16 entries.
func TestKeyRingBoundedByUint16(t *testing.T) {
	e := testEntry("kek", 1)
	kr := &KeyRing{Keys: make([]KeyRingEntry, 1<<16)}
	for i := range kr.Keys {
		kr.Keys[i] = e
	}
	if err := kr.Validate(); err != nil {
		t.Fatalf("a full ring must validate: %v", err)
	}
	kr.Keys = append(kr.Keys, e)
	if err := kr.Validate(); err == nil {
		t.Error("a ring past 1<<16 entries must not validate")
	}
}

// The identity is the first present entry's KeyID, and an empty ring has none.
func TestKeyRingKekIDIsTheKeyID(t *testing.T) {
	if got := (&KeyRing{}).KekID(); got != "" {
		t.Errorf("empty ring: identity = %q, want \"\"", got)
	}
	kr := &KeyRing{Keys: []KeyRingEntry{{}, testEntry("kek-instance", 1), testEntry("kek-instance", 2)}}
	if got := kr.KekID(); got != "kek-instance" {
		t.Errorf("identity = %q, want kek-instance", got)
	}
}

func TestCreateKeyRingDir(t *testing.T) {
	dir := t.TempDir()
	for range 2 {
		if err := CreateKeyRingDir(dir); err != nil {
			t.Fatalf("CreateKeyRingDir: %v", err)
		}
	}
	for _, d := range []string{KeyRingDir(dir), filepath.Join(KeyRingDir(dir), keyRingOpsDir)} {
		fi, err := os.Stat(d)
		if err != nil {
			t.Fatal(err)
		}
		if !fi.IsDir() || fi.Mode().Perm() != 0700 {
			t.Errorf("%s: mode %v, want a 0700 directory", d, fi.Mode())
		}
	}
}

// A missing ring is a fresh filesystem, and so is an empty ring directory. Loading creates nothing.
func TestLoadKeyRingMissing(t *testing.T) {
	dir := t.TempDir()
	kr, err := LoadKeyRing(dir)
	if err != nil {
		t.Fatalf("missing ring should load as empty: %v", err)
	}
	if len(kr.Keys) != 0 || kr.KekID() != "" {
		t.Errorf("missing ring loaded %d entries, identity %q", len(kr.Keys), kr.KekID())
	}
	if _, err := os.Lstat(KeyRingDir(dir)); !os.IsNotExist(err) {
		t.Errorf("LoadKeyRing created the ring: %v", err)
	}

	dir = ringCipherdir(t)
	if kr, err = LoadKeyRing(dir); err != nil || len(kr.Keys) != 0 {
		t.Errorf("empty ring directory: %d entries, %v; want 0, nil", len(kr.Keys), err)
	}
}

// A Phase-3 single-file ring is refused, not read as a fresh filesystem.
func TestLoadKeyRingRefusesRingFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(KeyRingDir(dir), []byte(`{"Keys":[]}`), 0400); err != nil {
		t.Fatal(err)
	}
	_, err := LoadKeyRing(dir)
	if err == nil {
		t.Fatal("a regular-file KR must be refused")
	}
	wantCode(t, err, exitcodes.LoadConf)
}

// Indices with no entry below the highest load as zero entries; names that are not entries are ignored.
func TestLoadKeyRingGaps(t *testing.T) {
	dir := ringCipherdir(t)
	writeEntry(t, dir, 1, testEntry("kek", 1))
	writeEntry(t, dir, 3, testEntry("kek", 3))
	for _, junk := range []string{"junk", "0004", "000004", "70000", "00005.bak", ".tmp.m.1", keyRingFormatName} {
		writeRingFile(t, dir, junk, []byte("not an entry"))
	}
	kr, err := LoadKeyRing(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(kr.Keys) != 4 {
		t.Fatalf("loaded %d entries, want 4", len(kr.Keys))
	}
	for i, wantMissing := range []bool{true, false, true, false} {
		if kr.Keys[i].Missing() != wantMissing {
			t.Errorf("entry %d: Missing = %v, want %v", i, kr.Keys[i].Missing(), wantMissing)
		}
	}
	if idx, _ := kr.ActiveIdx(); idx != 3 {
		t.Errorf("ActiveIdx = %d, want 3", idx)
	}
	if !bytes.Equal(kr.Keys[3].Ciphertext, testEntry("kek", 3).Ciphertext) || !kr.Keys[3].CreatedAt.Equal(testEntry("kek", 3).CreatedAt) {
		t.Errorf("entry 3 = %+v, want %+v", kr.Keys[3], testEntry("kek", 3))
	}
	if kr.KekID() != "kek" {
		t.Errorf("identity = %q, want kek", kr.KekID())
	}
}

// A malformed entry fails at load with LoadConf; without the code, exitcodes.Exit reports Other.
func TestLoadKeyRingRejectsMalformed(t *testing.T) {
	cases := map[string]string{
		"empty file":    ``,
		"not JSON":      `{"KeyID":`,
		"no KeyID":      `{"Ciphertext":"AQI=","CreatedAt":"2026-01-01T00:00:00Z"}`,
		"no Ciphertext": `{"KeyID":"kek","CreatedAt":"2026-01-01T00:00:00Z"}`,
		"no CreatedAt":  `{"KeyID":"kek","Ciphertext":"AQI="}`,
	}
	for name, js := range cases {
		t.Run(name, func(t *testing.T) {
			dir := ringCipherdir(t)
			writeRingFile(t, dir, "00000", []byte(js))
			_, err := LoadKeyRing(dir)
			if err == nil {
				t.Fatal("malformed entry must be rejected at load")
			}
			wantCode(t, err, exitcodes.LoadConf)
		})
	}
}

// The one-KEK rule also holds at load, with LoadConf.
func TestLoadKeyRingRejectsTwoKEKs(t *testing.T) {
	dir := ringCipherdir(t)
	writeEntry(t, dir, 0, testEntry("kek-1", 1))
	writeEntry(t, dir, 1, testEntry("kek-2", 2))
	_, err := LoadKeyRing(dir)
	if err == nil {
		t.Fatal("a ring naming two KEKs must be rejected at load")
	}
	wantCode(t, err, exitcodes.LoadConf)
}

// A publish on a free index wins, lands as a 0400 entry file with base64 ciphertext, and loads back.
func TestPublish(t *testing.T) {
	dir := ringCipherdir(t)
	kr, err := LoadKeyRing(dir)
	if err != nil {
		t.Fatal(err)
	}
	e := KeyRingEntry{KeyID: "kek", Ciphertext: []byte{1, 2, 3, 4}, CreatedAt: time.Unix(1000, 0).UTC()}
	won, err := kr.Publish(0, e, "m1")
	if err != nil || !won {
		t.Fatalf("Publish on a free index = %v, %v; want true, nil", won, err)
	}
	if len(kr.Keys) != 1 {
		t.Errorf("a won Publish left %d entries in the ring, want 1", len(kr.Keys))
	}
	path := filepath.Join(KeyRingDir(dir), "00000")
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0400 {
		t.Errorf("entry mode = %v, want 0400", fi.Mode().Perm())
	}
	js, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(js, []byte("AQIDBA==")) {
		t.Errorf("ciphertext {1,2,3,4} should appear base64-encoded (AQIDBA==) in %s", js)
	}
	if bytes.Contains(js, []byte("OpCount")) {
		t.Errorf("an entry no longer carries an op count: %s", js)
	}
	if won, err := kr.Publish(1, testEntry("kek", 5), "m1"); err != nil || !won {
		t.Fatalf("second Publish = %v, %v; want true, nil", won, err)
	}
	wantNoStaging(t, dir)

	loaded, err := LoadKeyRing(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Keys) != 2 {
		t.Fatalf("loaded %d entries, want 2", len(loaded.Keys))
	}
	for i, want := range kr.Keys {
		g := loaded.Keys[i]
		if g.KeyID != want.KeyID || !bytes.Equal(g.Ciphertext, want.Ciphertext) || !g.CreatedAt.Equal(want.CreatedAt) {
			t.Errorf("entry %d = %+v, want %+v", i, g, want)
		}
	}
}

// Only the next index can be published, and only an entry the ring would validate with.
func TestPublishRefused(t *testing.T) {
	dir := ringCipherdir(t)
	kr, err := LoadKeyRing(dir)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := kr.Publish(1, testEntry("kek", 1), "m1"); err == nil {
		t.Error("Publish of index 1 on an empty ring must fail")
	}
	if won, err := kr.Publish(0, testEntry("kek", 1), "m1"); err != nil || !won {
		t.Fatalf("Publish(0) = %v, %v", won, err)
	}
	if _, err := kr.Publish(0, testEntry("kek", 2), "m1"); err == nil {
		t.Error("Publish of an index the ring already holds must fail")
	}
	if _, err := kr.Publish(2, testEntry("kek", 2), "m1"); err == nil {
		t.Error("Publish past the next index must fail")
	}
	if _, err := kr.Publish(1, testEntry("other-kek", 2), "m1"); err == nil {
		t.Error("Publish of an entry under another KEK must fail")
	}
	if _, err := kr.Publish(1, KeyRingEntry{}, "m1"); err == nil {
		t.Error("Publish of an empty entry must fail")
	}
	if len(kr.Keys) != 1 {
		t.Errorf("refused publishes grew the ring to %d entries", len(kr.Keys))
	}
	if got := ringNames(t, dir); !slices.Equal(got, []string{"00000", keyRingNodesDir, keyRingOpsDir}) {
		t.Errorf("KR holds %v after refused publishes, want only 00000 and the directories", got)
	}
}

// Mounts racing on one index, each with its own ring, add one entry: one wins and every other is told it
// lost, without an error and without its entry in its ring.
func TestPublishRace(t *testing.T) {
	const n = 16
	dir := ringCipherdir(t)
	for round := range 3 {
		idx := uint16(round)
		start := make(chan struct{})
		var wg sync.WaitGroup
		won := make([]bool, n)
		errs := make([]error, n)
		rings := make([]*KeyRing, n)
		for i := range n {
			kr, err := LoadKeyRing(dir)
			if err != nil {
				t.Fatal(err)
			}
			rings[i] = kr
			wg.Add(1)
			go func() {
				defer wg.Done()
				<-start
				won[i], errs[i] = kr.Publish(idx, testEntry("kek", byte(round*n+i)), fmt.Sprintf("m%02d", i))
			}()
		}
		close(start)
		wg.Wait()
		winner := -1
		for i := range n {
			if errs[i] != nil {
				t.Errorf("round %d: publisher %d: %v", round, i, errs[i])
			}
			if won[i] {
				if winner >= 0 {
					t.Errorf("round %d: publishers %d and %d both won index %d", round, winner, i, idx)
				}
				winner = i
			}
			wantLen := int(idx)
			if won[i] {
				wantLen++
			}
			if len(rings[i].Keys) != wantLen {
				t.Errorf("round %d: publisher %d (won=%v) holds %d entries, want %d", round, i, won[i], len(rings[i].Keys), wantLen)
			}
		}
		if winner < 0 {
			t.Fatalf("round %d: nobody won index %d", round, idx)
		}
		loaded, err := LoadKeyRing(dir)
		if err != nil {
			t.Fatal(err)
		}
		if len(loaded.Keys) != int(idx)+1 {
			t.Fatalf("round %d: ring has %d entries, want %d", round, len(loaded.Keys), idx+1)
		}
		if want := testEntry("kek", byte(round*n+winner)); !bytes.Equal(loaded.Keys[idx].Ciphertext, want.Ciphertext) {
			t.Errorf("round %d: entry %d is %v, want the winner's %v", round, idx, loaded.Keys[idx].Ciphertext, want.Ciphertext)
		}
	}
	wantNoStaging(t, dir)
}

// An existing byte-identical dst is a link that landed although NFS reported it failed, so it counts
// as won; a different one is lost.
func TestPublishExclusive(t *testing.T) {
	dir := ringCipherdir(t)
	staging := KeyRingDir(dir)
	data := []byte("ours")

	fresh := filepath.Join(dir, "fresh")
	if won, err := PublishExclusive(fresh, data, 0444, staging, "m1"); err != nil || !won {
		t.Errorf("absent dst: %v, %v; want true, nil", won, err)
	}
	if got, _ := os.ReadFile(fresh); !bytes.Equal(got, data) {
		t.Errorf("dst = %q, want %q", got, data)
	}
	if fi, err := os.Stat(fresh); err != nil || fi.Mode().Perm() != 0444 {
		t.Errorf("dst mode = %v (%v), want the mode asked for", fi.Mode().Perm(), err)
	}

	same := filepath.Join(dir, "same")
	if err := os.WriteFile(same, data, 0400); err != nil {
		t.Fatal(err)
	}
	if won, err := PublishExclusive(same, data, 0400, staging, "m1"); err != nil || !won {
		t.Errorf("byte-identical dst: %v, %v; want true, nil", won, err)
	}

	other := filepath.Join(dir, "other")
	if err := os.WriteFile(other, []byte("theirs"), 0400); err != nil {
		t.Fatal(err)
	}
	if won, err := PublishExclusive(other, data, 0400, staging, "m1"); err != nil || won {
		t.Errorf("different dst: %v, %v; want false, nil", won, err)
	}
	if got, _ := os.ReadFile(other); string(got) != "theirs" {
		t.Errorf("a lost publish changed dst to %q", got)
	}
	wantNoStaging(t, dir)
}

// Refresh learns the entries another ring value published, and a bad one leaves the ring as it was.
func TestRefresh(t *testing.T) {
	dir := ringCipherdir(t)
	a, err := LoadKeyRing(dir)
	if err != nil {
		t.Fatal(err)
	}
	b, err := LoadKeyRing(dir)
	if err != nil {
		t.Fatal(err)
	}
	if grew, err := b.Refresh(); err != nil || grew != 0 {
		t.Errorf("Refresh of an unchanged ring = %d, %v; want 0, nil", grew, err)
	}
	for i := range uint16(2) {
		if won, err := a.Publish(i, testEntry("kek", byte(i)), "a"); err != nil || !won {
			t.Fatalf("Publish(%d) = %v, %v", i, won, err)
		}
	}
	if grew, err := b.Refresh(); err != nil || grew != 2 {
		t.Fatalf("Refresh = %d, %v; want 2, nil", grew, err)
	}
	if len(b.Keys) != 2 || !bytes.Equal(b.Keys[1].Ciphertext, a.Keys[1].Ciphertext) {
		t.Errorf("refreshed ring = %+v, want %+v", b.Keys, a.Keys)
	}
	if grew, err := b.Refresh(); err != nil || grew != 0 {
		t.Errorf("second Refresh = %d, %v; want 0, nil", grew, err)
	}
	if won, err := b.Publish(2, testEntry("kek", 2), "b"); err != nil || !won {
		t.Fatalf("Publish after Refresh = %v, %v", won, err)
	}
	if grew, err := a.Refresh(); err != nil || grew != 1 {
		t.Errorf("Refresh of the other ring = %d, %v; want 1, nil", grew, err)
	}

	writeEntry(t, dir, 4, testEntry("other-kek", 4))
	_, err = a.Refresh()
	if err == nil {
		t.Fatal("Refresh must refuse an entry under another KEK")
	}
	wantCode(t, err, exitcodes.LoadConf)
	if len(a.Keys) != 3 {
		t.Errorf("a refused Refresh changed the ring to %d entries", len(a.Keys))
	}
}

func opsPath(cipherdir, name string) string {
	return filepath.Join(KeyRingDir(cipherdir), keyRingOpsDir, name)
}

// Shards round-trip and replace their predecessor; an unparsable one is Bad, a vanished one and names
// that are not shards are skipped.
func TestOpShards(t *testing.T) {
	dir := ringCipherdir(t)
	kr, err := LoadKeyRing(dir)
	if err != nil {
		t.Fatal(err)
	}
	if shards, err := kr.OpShards(); err != nil || len(shards) != 0 {
		t.Fatalf("OpShards on a fresh ring = %v, %v", shards, err)
	}
	for _, w := range []struct {
		idx   uint16
		mount string
		total uint64
	}{{0, "a", 5}, {2, "a", 7}, {2, "b", 9}, {2, "a", 11}} {
		if err := kr.WriteOpShard(w.idx, w.mount, w.total); err != nil {
			t.Fatalf("WriteOpShard(%d, %s, %d): %v", w.idx, w.mount, w.total, err)
		}
	}
	old := time.Now().Add(-time.Hour).Truncate(time.Second)
	if err := os.Chtimes(opsPath(dir, "00002.b"), old, old); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(opsPath(dir, "00003.bad"), []byte("garbage"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("vanished", opsPath(dir, "00004.gone")); err != nil {
		t.Fatal(err)
	}
	for _, junk := range []string{"junk", "00001.", "1.x", "70000.x"} {
		if err := os.WriteFile(opsPath(dir, junk), []byte(`{"Count":1}`), 0600); err != nil {
			t.Fatal(err)
		}
	}
	wantNoStaging(t, dir)

	shards, err := kr.OpShards()
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]OpShard{}
	for _, s := range shards {
		got[fmt.Sprintf("%d.%s", s.Idx, s.MountID)] = s
	}
	want := map[string]uint64{"0.a": 5, "2.a": 11, "2.b": 9, "3.bad": 0}
	if len(got) != len(want) || len(shards) != len(want) {
		t.Errorf("OpShards = %+v, want the shards %v", shards, want)
	}
	for k, count := range want {
		s, ok := got[k]
		if !ok {
			t.Errorf("shard %s missing", k)
			continue
		}
		if s.Count != count || s.Bad != (k == "3.bad") {
			t.Errorf("shard %s: Count %d, Bad %v", k, s.Count, s.Bad)
		}
	}
	if !got["2.b"].ModTime.Equal(old) {
		t.Errorf("shard 2.b ModTime = %v, want %v", got["2.b"].ModTime, old)
	}
	if time.Since(got["2.a"].ModTime) > time.Minute {
		t.Errorf("shard 2.a ModTime = %v, want now", got["2.a"].ModTime)
	}

	for range 2 {
		if err := kr.RemoveOpShard(got["2.a"]); err != nil {
			t.Errorf("RemoveOpShard: %v", err)
		}
	}
	if err := kr.RemoveOpShard(got["3.bad"]); err != nil {
		t.Errorf("RemoveOpShard of a Bad shard: %v", err)
	}
	if shards, err = kr.OpShards(); err != nil || len(shards) != 2 {
		t.Errorf("after removals OpShards = %+v, %v; want 0.a and 2.b", shards, err)
	}
}

// Only staging files past the age go; entries, the format record and other files stay however old.
func TestRemoveStaleStaging(t *testing.T) {
	dir := ringCipherdir(t)
	writeEntry(t, dir, 0, testEntry("kek", 0))
	writeRingFile(t, dir, keyRingFormatName, []byte("{}"))
	writeRingFile(t, dir, keyRingXattrLock, nil)
	writeRingFile(t, dir, ".tmp.dead.1", []byte("x"))
	writeRingFile(t, dir, ".tmp.live.2", []byte("x"))
	if err := os.WriteFile(opsPath(dir, ".tmp.dead.3"), []byte("x"), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-2 * time.Hour)
	for _, p := range []string{"00000", keyRingFormatName, keyRingXattrLock, ".tmp.dead.1"} {
		if err := os.Chtimes(filepath.Join(KeyRingDir(dir), p), old, old); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Chtimes(opsPath(dir, ".tmp.dead.3"), old, old); err != nil {
		t.Fatal(err)
	}
	kr, err := LoadKeyRing(dir)
	if err != nil {
		t.Fatal(err)
	}
	kr.RemoveStaleStaging(time.Hour)
	want := []string{".tmp.live.2", "00000", keyRingFormatName, keyRingNodesDir, keyRingOpsDir, keyRingXattrLock}
	slices.Sort(want)
	if got := ringNames(t, dir); !slices.Equal(got, want) {
		t.Errorf("KR holds %v, want %v", got, want)
	}
	if _, err := os.Stat(opsPath(dir, ".tmp.dead.3")); err != nil {
		t.Errorf("a file outside KR/ was touched: %v", err)
	}
}

func testFormatConf() *ConfFile {
	return &ConfFile{
		Version:      contentenc.CurrentVersion,
		FeatureFlags: []string{knownFlags[FlagGCMIV128], knownFlags[FlagDirIV], knownFlags[FlagEMENames]},
		LongNameMax:  0,
		NodeID:       "node-1",
	}
}

// The first mount records the format; later configs must match it, flag order and NodeID aside.
func TestCheckFormat(t *testing.T) {
	dir := ringCipherdir(t)
	path := filepath.Join(KeyRingDir(dir), keyRingFormatName)
	if err := CheckFormat(dir, testFormatConf(), "m1", false); err != nil {
		t.Fatalf("first CheckFormat: %v", err)
	}
	recorded, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("the first mount did not record the format: %v", err)
	}
	reordered := testFormatConf()
	slices.Reverse(reordered.FeatureFlags)
	if err := CheckFormat(dir, reordered, "m2", false); err != nil {
		t.Errorf("the same config in another flag order: %v", err)
	}
	if err := CheckFormat(dir, testFormatConf(), "m2", true); err != nil {
		t.Errorf("the same config, read-only: %v", err)
	}
	ownNode := testFormatConf()
	ownNode.NodeID = "node-2"
	if err := CheckFormat(dir, ownNode, "m2", false); err != nil {
		t.Errorf("a config with its own NodeID: %v", err)
	}

	differ := map[string]func(*ConfFile){
		"FeatureFlags": func(cf *ConfFile) { cf.FeatureFlags = append(cf.FeatureFlags, knownFlags[FlagRaw64]) },
		"LongNameMax":  func(cf *ConfFile) { cf.LongNameMax = 100 },
		"Version":      func(cf *ConfFile) { cf.Version++ },
	}
	for name, change := range differ {
		cf := testFormatConf()
		change(cf)
		for _, ro := range []bool{false, true} {
			err := CheckFormat(dir, cf, "m3", ro)
			if err == nil {
				t.Errorf("a different %s (read-only %v) must be refused", name, ro)
				continue
			}
			wantCode(t, err, exitcodes.LoadConf)
		}
	}
	if got, _ := os.ReadFile(path); !bytes.Equal(got, recorded) {
		t.Errorf("format record changed from %s to %s", recorded, got)
	}
	wantNoStaging(t, dir)
}

// A read-only mount of a ring with no format record compares nothing and records nothing.
func TestCheckFormatReadOnlyCreatesNothing(t *testing.T) {
	dir := t.TempDir()
	if err := CheckFormat(dir, testFormatConf(), "m1", true); err != nil {
		t.Errorf("read-only, no ring: %v", err)
	}
	if _, err := os.Lstat(KeyRingDir(dir)); !os.IsNotExist(err) {
		t.Errorf("read-only CheckFormat created the ring: %v", err)
	}
	dir = ringCipherdir(t)
	if err := CheckFormat(dir, testFormatConf(), "m1", true); err != nil {
		t.Errorf("read-only, no record: %v", err)
	}
	if got := ringNames(t, dir); !slices.Equal(got, []string{keyRingNodesDir, keyRingOpsDir}) {
		t.Errorf("read-only CheckFormat left %v in KR", got)
	}
}

// flock conflicts between open file descriptions, so two opens in one process stand in for two mounts.
func TestLockKeyRing(t *testing.T) {
	dir := t.TempDir()
	lock := func(shared bool) *os.File {
		t.Helper()
		f, err := LockKeyRing(dir, shared, 0)
		if err != nil {
			t.Fatalf("LockKeyRing(shared=%v): %v", shared, err)
		}
		return f
	}
	refused := func(shared bool, why string) {
		t.Helper()
		if f, err := LockKeyRing(dir, shared, 0); !errors.Is(err, ErrKeyRingInUse) {
			if f != nil {
				f.Close()
			}
			t.Errorf("%s: err = %v, want ErrKeyRingInUse", why, err)
		}
	}

	sh1, sh2 := lock(true), lock(true)
	refused(false, "exclusive while shared are held")
	sh1.Close()
	refused(false, "exclusive while one shared is held")
	sh2.Close()

	ex := lock(false)
	refused(true, "shared while exclusive is held")
	refused(false, "exclusive while exclusive is held")
	// A holder that lets go within the wait, as an exiting mount does, is waited out.
	go func() {
		time.Sleep(100 * time.Millisecond)
		ex.Close()
	}()
	again, err := LockKeyRing(dir, true, 5*time.Second)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	again.Close()
}

// One live mount per NodeID; other NodeIDs lock independently, any NodeID makes a file name, and a
// released NodeID is free again.
func TestLockNodeID(t *testing.T) {
	dir := t.TempDir()
	if err := CreateKeyRingDir(dir); err != nil {
		t.Fatal(err)
	}
	long, err := LockNodeID(dir, strings.Repeat("n", 300), 0)
	if err != nil {
		t.Fatalf("a NodeID longer than a file name: %v", err)
	}
	long.Close()
	a, err := LockNodeID(dir, "node/a", 0)
	if err != nil {
		t.Fatal(err)
	}
	if f, err := LockNodeID(dir, "node/a", 0); !errors.Is(err, ErrNodeIDInUse) {
		if f != nil {
			f.Close()
		}
		t.Fatalf("second lock of a held NodeID: err = %v, want ErrNodeIDInUse", err)
	}
	b, err := LockNodeID(dir, "node-b", 0)
	if err != nil {
		t.Fatalf("another NodeID: %v", err)
	}
	b.Close()
	a.Close()
	again, err := LockNodeID(dir, "node/a", time.Second)
	if err != nil {
		t.Fatalf("lock after release: %v", err)
	}
	again.Close()
}

// A writable mount meets an earlier version's ring file in CreateKeyRingDir, and gets the same refusal.
func TestCreateKeyRingDirRefusesRingFile(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(KeyRingDir(dir), []byte(`{"Keys":[]}`), 0400); err != nil {
		t.Fatal(err)
	}
	err := CreateKeyRingDir(dir)
	if err == nil {
		t.Fatal("a regular-file KR must be refused")
	}
	wantCode(t, err, exitcodes.LoadConf)
}
