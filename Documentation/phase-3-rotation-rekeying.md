# Phase 3 — Rotation & rekeying (TK-1393)

Phase 2 gave the filesystem one gateway-issued data key, stored as ciphertext in the `KR` key ring
and unwrapped at mount. Phase 3 makes that a ring of *several* keys: new data is written under the
newest, old data stays readable under the key that wrote it.

Design settled 2026-08-06, implemented 2026-08-07 across four repos on the branch
`feature/tkfs-v2-phase3-rotation-rekeying` (gocryptfs off `feature/tkfs-v2`@`257f492`, tkutils `1ab6a63`,
keep `b5406793`, gatehouse `4a926678`).

Sections marked *"corrected during implementation"* or *"found during implementation"* are where contact
with the code changed the design. §15 records every open item's resolution and what the build surfaced
that code reading had not.

---

## 0. Settled decisions, and why

These were argued out before any code was written. The rationale matters more than the conclusion —
several of them reverse an earlier draft of this design.

**0.1 — Every encrypted object carries an explicit key index. There is no trial decryption anywhere,
and a missing index is an error, never a default of 0.**

An earlier draft leaned on AES-GCM's authentication tag: for headerless-but-authenticated objects
(symlink targets, xattr values) you can simply try each key and let the tag say which one worked, at
a false-accept probability of 2⁻¹²⁸. That is sound cryptography, and it was rejected anyway. One rule
that holds everywhere is worth more than a second mechanism that is only *probably* fine, and an
explicit index turns "no key worked" into "written under index 3, which this mount has no key for".

**0.2 — The name key rotates too.**

The first draft pinned filename encryption to a single never-rotated key, justified on volume:
filenames are a rounding error next to file content, and rotation bounds how much data sits under one
key. That reasoning covers only half of what rotation is for. The other half is recovering from a
compromise — and a never-rotating name key means whoever obtains it reads **every filename the
filesystem will ever have**, including all future ones. Rotation that leaves that hole open is partly
theatre. So: N name keys and N content keys.

**0.3 — The name-key index lives in the directory, in `gocryptfs.diriv`.**

Filenames cannot carry their own index. A filename *is* its ciphertext — there is no header, no
sidecar, no spare field — and lookup runs the cipher **forward**: `Lookup` takes a plaintext name,
encrypts it, and does one `openat` on the result. The reader must choose a key *before* it has any
ciphertext to test, so a per-name marker cannot help the hot path; it would only help `Readdir`, and
would still cost N syscalls per lookup. The directory's IV file is read and cached before any name in
that directory is encrypted, which makes it the one place an index arrives in time.

Appending the index to each encrypted name was considered and rejected: it does not help lookup at
all, it lengthens every name (pushing more of them over the long-name threshold, which changes their
on-disk identity), and it publishes in the clear which entries predate which rotation — an age
ordering the encryption otherwise hides.

**0.4 — Xattr names are keyed by a per-inode marker.**

**Revised 2026-08-07, after an adversarial review found the previous answer to be wrong.** Both earlier
schemes failed, and the reason the second one failed is the more interesting of the two.

**A filename is a property of a directory entry. An xattr name is a property of an inode.** `Rename`
re-encrypts a filename under the destination directory's key, so a filename keyed by its directory stays
correct by construction. An inode's stored xattr names are not touched when the inode moves — so keying
them by the directory the inode *currently sits in* means a `mv` across a rotation boundary silently
changes which key addresses them. `Getxattr` then returns ENODATA for an attribute that exists,
`Removexattr` removes nothing, `Setxattr` writes a *second* attribute, and `Listxattr` fails to decrypt
and skips it as mitigated corruption. The mount holds both keys and quietly picks the wrong one. The root
directory's index is pinned for the filesystem's life, so `mv <root file> <post-rotation dir>/` is enough
to trigger it.

**Re-encrypting on rename cannot fix this, even in principle.** A hard link makes one inode reachable from
two directories with *different* indices at the same time, so no single stored encoding satisfies both.
Location-keyed inode metadata is unsatisfiable, not merely awkward — which is what makes a fixed index the
answer rather than a compromise.

So the index lives on the inode: an empty backing xattr named `user.gocryptfs_keyidx.<n>`, stamped with the
current write index by the inode's first encrypted xattr and never changed. Every encrypted xattr name on
that inode is encrypted under `<n>`, so a rename or a hard link carries the right index along, and names
rotate the way file content does — forward, as inodes get their first xattr.

The index is in the marker's *name*, not its value, because `Listxattr` and `Setxattr` must work without
read permission (upstream's `TestList0000File`, `TestSet0200File`), and listing names needs none. An inode
with encrypted names but no marker is corrupt: its names are refused, not decrypted under a guessed index.
A mutex around the stamping keeps two concurrent first sets from stamping two indices, which one process
per filesystem (§15.1) makes sufficient.

An earlier revision pinned xattr names to ring index 0 in every mode instead: correct, but they never
rotated.

The rest of this section records the two rejected schemes, since both dead ends are instructive.

**Rejected: a dot-suffix on the stored xattr name.**

A dot-suffix on the stored xattr name (`user.gocryptfs.<b64>.<idx>`) was approved and then withdrawn.
It solves `Listxattr`, which reads backward, but breaks every name-directed operation: `Getxattr`,
`Setxattr` and `Removexattr` all construct the backing name forward from the plaintext
([node_xattr.go](../internal/fusefrontend/node_xattr.go)). After a rotation the
constructed name cannot match one stored under an older index — `Getxattr` returns ENODATA for an
attribute that exists, `Removexattr` removes nothing, `Setxattr` writes a *second* xattr, `Listxattr`
then emits the same plaintext name twice, and `XATTR_CREATE` succeeds where it must fail EEXIST.
Probing N candidate names works but needs a read-modify-write on every set plus duplicate handling.

**Rejected: the parent directory's index**, which is what the previous draft chose, on the grounds that all
four xattr operations already call `prepareAtSyscallMyself()` and so have the dirfd in hand
([node_xattr_linux.go](../internal/fusefrontend/node_xattr_linux.go)). Its one-sentence rule was
"names of things in a directory — filenames and xattr names alike — use that directory's key". That
sentence is the error: it treats two different kinds of thing as one, and everything above follows from
that. It was also not free, as claimed — the ops call `prepareAtSyscallMyself()` *inside*
`getXAttr`/`setXAttr`, after the caller has already constructed the encrypted name, so it needed a second
prepare via an `xattrKeyIdx()` helper and a fourth return value threaded through
`prepareAtSyscall`. Removing it shrinks the fork's delta against upstream, which is the small consolation.

**0.5 — Every directory gets a `gocryptfs.diriv` — except under `-plaintextnames`.**

`-deterministic-names` now creates the file it used to omit, with a fixed all-zero IV, so the index
always has a carrier there. Carrying an otherwise-unused 16-byte IV is cheaper than an exception in the
key-selection path.

**`-plaintextnames` keeps its current behaviour: no diriv at all.** Extending the universal rule to that
mode was considered and rejected, because there it is the *expensive* option:

- `isFiltered` deliberately does not reserve the name — "diriv and plaintextnames are exclusive"
  ([root_node.go](../internal/fusefrontend/root_node.go)) — and `TestFiltered`
  ([plaintextnames_linux_test.go](../tests/plaintextnames/plaintextnames_linux_test.go)) asserts a
  user *can* create a plaintext file called `gocryptfs.diriv`. Reserving it is a user-visible regression.
  (It does reserve `KR` and `KR.tmp`, beside `gocryptfs.conf`: those live in the cipherdir root in
  every mode.)
- `Readdirent` returns early for `PlaintextNames` before the diriv filter
  ([file_dir_ops.go](../internal/fusefrontend/file_dir_ops.go)), so the carrier would be a visible
  entry.
- `Validate` actively refuses `FlagDirIV` together with `FlagPlaintextNames`
  ([validate.go](../internal/configfile/validate.go)).

Xattr names are the only EME-encrypted objects in that mode — `encryptXattrName` is not gated on the
flag ([root_node.go](../internal/fusefrontend/root_node.go)) — and they take their index from the per-inode
marker (§0.4) exactly as in every other mode, which needs no diriv.

**0.6 — The root diriv moves from `-init` to first mount.**

`-init` writes the root diriv today, but since the Phase-2 redesign `-init` never contacts the key
service: the ring is minted on first mount. At `-init` time there is no ring and therefore no index to
write, and writing 0 is exactly the default that 0.1 forbids. Root diriv creation moves next to
`generateInitialDataKey`, where a ring exists. Verified cheap:
`ensureCipherdirFresh` *whitelists* rather than requires the diriv
([mount.go](../mount.go)), so both orderings stay legal and it needs no change.

The diriv is written and synced **before** the ring is persisted. A mount that finds a ring never comes
back to write the root diriv, so a crash between the two must leave no ring (the next mount starts over
and replaces the leftover diriv) rather than a ring with no root diriv, under which no path resolves.

**0.7 — Errors are contained to the directory that has them.**

A directory whose diriv is unreadable or index-less fails *that directory*. Siblings and unrelated
subtrees keep working. This is already how the code behaves — every diriv is read lazily by the
directory that needs it — so it costs nothing to preserve, and the thing to avoid is adding an eager
"validate every diriv at mount" pass that would convert a contained failure into a global one.

**0.8 — Same containment for a content key the key service will not return.**

If a historical ring entry fails to unwrap at mount, the files under that key fail; the mount
proceeds. Unlike a malformed filesystem, an unavailable key is an outside condition, and refusing the
whole mount over one revoked historical key is a harsher outcome than refusing the files that need it.
Two entries are exempt, and failing to unwrap either is fatal: the *active* one, which every write
needs, and — unless names are plaintext — index 0, which the root diriv names, so without it no path
resolves.

**0.9 — No on-disk format version bump.** The format is work in progress and v3 is unreleased. Existing
v3 filesystems (16-byte dirivs, unmarked symlink targets and xattr values) stop working; there are no
checked-in fixtures left, so the cost is scratch filesystems only. *One hidden fixture surfaced during
implementation:* `tests/xattr` hand-built a v3-era diriv at `TestMain` (see §13), so "no checked-in
fixtures" was true of the fixture directories but not of the test code.

**0.10 — A key-ring index is the entry's position in `KR`.** Entries are append-only for that reason.
See §9.

---

## 1. Scope

**Delivers:** a multi-key ring; per-object key selection for content, names, symlink targets and xattr
values; rotation that appends a key and switches new writes to it; old data readable indefinitely.

**Does not deliver:** re-encryption of existing data. Rotation is forward-only — see §14 for exactly
what that leaves exposed, which is a property the ticket should state rather than imply away.

---

## 2. The key model

The ring holds N entries. Each entry's 32-byte master key HKDF-derives two independent keys, exactly
as today (`cryptocore.New`, [cryptocore.go](../internal/cryptocore/cryptocore.go)): an EME key for names and an
AEAD key for content. Both halves of every entry are live — names and content rotate together.

| Object | Key | Where the index comes from |
|---|---|---|
| Regular file content | content | `KeyIdx` in the 20-byte file header — **exists today** |
| Symlink target | content | 2-byte prefix inside the encrypted blob — new |
| Xattr value | content | 2-byte prefix — new |
| Filename | name (EME) | the directory's `gocryptfs.diriv` — new |
| Xattr name | name (EME) | the inode's `user.gocryptfs_keyidx.<n>` marker — new (§0.4) |
| Long-name `.name` sidecar | name (EME) | inherits its directory's index (§4) |

Four markers, not five: the long-name sidecar inherits one.

Under `-plaintextnames` filenames are not encrypted, so xattr names are the only part of the name half that
rotates there.

---

## 3. On-disk format

`keyIdx` is **`uint16`, big-endian**, everywhere, matching the existing file header.

### 3.1 File content — unchanged

```
[ Version uint16 ][ KeyIdx uint16 ][ ID 16B ]   = 20 bytes, then encrypted blocks
```

Already shipped in Phase 2. `KeyIdx` stays outside the AAD: the AEAD tag already binds the key that
was used, so authenticating the selector adds nothing.

### 3.2 Symlink target — new prefix

```
before:  base64(           nonce 16B || ciphertext || tag 16B )
after:   base64( KeyIdx 2B || nonce 16B || ciphertext || tag 16B )
```

Inside the base64, prepended, so the stored target stays a single token with no separator to parse and
the index sits at a fixed offset. A 9-byte target goes from 41 to 43 bytes, 55 to 58 base64 characters.

### 3.3 Xattr value — new prefix

```
before:  nonce 16B || ciphertext || tag 16B          (raw bytes, not base64)
after:   KeyIdx 2B || nonce 16B || ciphertext || tag 16B
```

The base64 backward-compat fallback in `decryptXattrValue`
([root_node.go](../internal/fusefrontend/root_node.go)) is **deleted**: it exists for pre-v3
filesystems that v3 already refuses to mount, and it is the only remaining multi-path decrypt.

*Gap found during implementation:* "test the empty case, then read the prefix" (§4) is not sufficient on
its own. Taken literally, a **2-byte** value passes the empty test, splits into a valid index and *zero*
ciphertext, and `DecryptBlock` returns that as an empty plaintext **with no error** — a silent accept of
corrupt data. The split must require at least one byte after the prefix. The same reasoning applies to any
future prefixed field: "non-empty" and "has a payload" are different tests.

### 3.4 `gocryptfs.diriv` — 16 → 18 bytes

```
[ IV 16B ][ KeyIdx 2B ]
```

A 16-byte file is an error, not "index absent, assume 0".

### 3.5 Xattr name — per-inode marker

`user.gocryptfs.<base64>` exactly as today. The index is carried once per inode, in an empty backing xattr
named `user.gocryptfs_keyidx.<n>` (decimal), written by the inode's first encrypted xattr (§0.4).
`Listxattr` skips it, since it lacks the `user.gocryptfs.` prefix. No marker means no encrypted xattrs; a
duplicate or malformed one is EIO.

---

## 4. Index-free objects — deliberate exemptions

These carry no index because they contain no ciphertext to key. Every decrypt path must test for the
empty case **before** reading an index prefix.

- **Empty xattr values** — `encryptXattrValue` returns empty unchanged
  ([root_node.go](../internal/fusefrontend/root_node.go)).
- **Empty symlink targets** — passed through in both directions; unreachable via `symlink(2)`, but the
  read path accepts them.
- **Zero-length files** — no header exists until the first write, so no index exists.
- **All-zero (sparse) ciphertext blocks** — `DecryptBlock` returns a zero plaintext block without
  consulting a key ([content.go](../internal/contentenc/content.go)).
- **The long-name `.name` sidecar** — holds an EME-encrypted filename and inherits its directory's
  index. Sound only because every directory now has a diriv, which is why §0.5 and §0.6 are
  load-bearing rather than tidy-up.
- **The `gocryptfs.longname.<sha256>` hash name** — unkeyed SHA-256, but computed over the *ciphertext*
  name, so it is key-dependent: a long name cannot be located without the directory's index first, and
  re-keying a directory renames both halves of the pair.
- **`gocryptfs.diriv.rmdir.<rand>`** — the diriv is briefly moved into the parent during `Rmdir`
  ([node_dir_ops.go](../internal/fusefrontend/node_dir_ops.go)). Pre-existing behaviour,
  unchanged by this phase, but it now means a keyIdx-bearing file can be orphaned outside its directory
  by an interrupted rmdir.

---

## 5. `cryptocore` — N cores, one nonce source

Each ring entry gets a full `CryptoCore` (EME cipher + content AEAD), so `cryptocore.New` is called N
times and **its signature does not change**.

The one change inside the package: `newNonceGenerator` currently starts a goroutine per core feeding a
500-slot buffered channel ([nonce.go](../internal/cryptocore/nonce.go)). N cores would leave N−1
parked goroutines holding pre-generated nonces for keys that are never written under. Memoize the
generator by nonce length instead. This is also *more* correct than what exists: nonces come from
`tkutils` `crypto.NextNonce`, an 8-byte process-global atomic counter plus a random tail, so a single
source per length is the honest expression of what already happens.

Only the active entry's core survives `buildKeySets` — the others are discarded once their AEAD and EME
ciphers are extracted — so exactly one `cryptocore.Wipe()` runs at unmount. It nils stdlib cipher
references and forces a GC; the per-index ciphers are dropped by `contentenc.Wipe` and
`nametransform.Wipe`, which is why names are wiped first.

---

## 6. `contentenc` — the content key set

The set is read on every block by many goroutines and grows while mounted, so it is copy-on-write
behind an atomic pointer rather than a mutex on the hot path:

```go
type keySet struct {
    aeads    []cipher.AEAD // index-aligned with the key ring
    writeIdx uint16
}

type ContentEnc struct {
    cryptoCore *cryptocore.CryptoCore // primary: IVLen, IVGenerator
    keys       atomic.Pointer[keySet]
    ...
}
```

- `aeadForKey(keyIdx)` — load the snapshot, range-check, return the AEAD, or an error naming the index
  and the ring size. Replaces today's "index ≠ 0 is an error" stub
  ([content.go](../internal/contentenc/content.go)).
- `WriteKeyIdx() uint16` — from the snapshot. Replaces `const WriteKeyIdx = 0`.
- `AddKey(cipher.AEAD)` — builds a new slice with one more entry and stores it. Never mutates in place,
  so in-flight readers keep a consistent view. This is rotation's entry point.
- `Wipe()` — publishes an all-nil snapshot rather than clearing the live one, so a read that overlaps it
  sees the old set or a clean hole. It leaves `cryptoCore` in place: five hot-path reads of it are
  unsynchronized, and `cryptocore.Wipe()` already drops everything it can reach.

Preserve `aeadForKey`'s asymmetry: an unresolvable index is an **error on the read path** (it comes
from an untrusted header) but a **panic on the write path** (writes only ever use a key the mount
holds). Both comments state this deliberately, on `aeadForKey` and in `doEncryptBlock`
([content.go](../internal/contentenc/content.go)).

`IVLen` and `IVGenerator` stay on the primary core — they are properties of the backend, not the key,
and writes only ever use the newest key.

---

## 7. `nametransform` — the name key set

`NameTransform` holds N EME ciphers and its methods take an index: `EncryptName`, `DecryptName`,
`EncryptAndHashName`, `EncryptXattrName`, `DecryptXattrName`, and `EncryptAndHashBadName`
([badname.go](../internal/nametransform/badname.go), which re-encrypts a prefix to recover a
partially-corrupt entry and needs the same index).

Internally the blast radius is two lines — `emeCipher` is touched only in `decryptName` and
`encryptName` ([names.go](../internal/nametransform/names.go)). The cost is threading the index through
the public methods and their callers.

**This diverges from upstream deliberately.** `names.go` is currently byte-identical to upstream HEAD
and the standing rule is to keep it that way. Name rotation makes that impossible. Unlike the `raw64`
delta, this buys something real, but it is a considered divergence and should be recorded as one.

---

## 8. `gocryptfs.diriv` — carries the name index (all modes but `-plaintextnames`)

**`ReadDirIVAt` must not return the 18-byte record as one slice.** `eme` hard-panics on a tweak that is
not exactly 16 bytes (`eme@v1.1.2/eme.go:121`), and five call sites feed its return value straight into
`EncryptName`/`DecryptName`: [node_prepare_syscall.go](../internal/fusefrontend/node_prepare_syscall.go),
[file_dir_ops.go](../internal/fusefrontend/file_dir_ops.go),
[ctlsock_interface.go](../internal/fusefrontend/ctlsock_interface.go),
[longnames.go](../internal/nametransform/longnames.go). The API becomes `(iv []byte, keyIdx uint16, err error)`.

`DirIVLen` keeps meaning *the IV* (16); a separate constant names the file length (18), so
`NewRootNode`'s `ivLen` ([root_node.go](../internal/fusefrontend/root_node.go)) is untouched.

Other required changes, in the order they must be made:

1. **`fdReadDirIV`** — length check 16 → 18, rejecting a 16-byte file rather than defaulting. It becomes
   a method on `*NameTransform`, because the all-zero-IV rejection
   ([diriv.go](../internal/nametransform/diriv.go)) **inverts** under `-deterministic-names`:
   all-zero is the only legal value there and a corruption signal everywhere else.
2. **`ReadDirIVAt`** — the `deterministicNames` short-circuit goes; the file must be read for its index.
3. **`WriteDirIVAt`** — takes the index to write.
4. **`mkdirWithIv`** ([node_dir_ops.go](../internal/fusefrontend/node_dir_ops.go)) — the
   `DeterministicNames` early return goes. That path currently skips the `dirIVLock` *and* the
   rollback-on-failure that the randomized path has; adding a diriv write without them would let a
   concurrent reader see a directory with no diriv, and leave permanently unreadable directories behind
   on failure. Its `PlaintextNames` branch is **unchanged** — that mode keeps its no-diriv
   behaviour (§0.5).
5. **`Rmdir`** ([node_dir_ops.go](../internal/fusefrontend/node_dir_ops.go)) — the deterministic
   short-circuit does a bare `Unlinkat(AT_REMOVEDIR)`; once a diriv exists that returns ENOTEMPTY. It
   also silently breaks rename-over-an-empty-directory, which calls `Rmdir` internally.
6. **`Readdirent`** ([file_dir_ops.go](../internal/fusefrontend/file_dir_ops.go)) — the diriv filter
   becomes unconditional. Leaving it conditional does more than expose the file: the name falls through
   to `DecryptName`, fails, and is reported via `tlog.Warn` + `reportMitigatedCorruption`
   ([file_dir_ops.go](../internal/fusefrontend/file_dir_ops.go)) — so fsck would flag every
   directory in the filesystem, and because **every test mount passes `-wpanic`**
   ([mount_unmount.go](../tests/test_helpers/mount_unmount.go), [log.go](../internal/tlog/log.go))
   that warning is a mount panic in the entire test suite, not a log line.

   Items 4, 5 and 6 must land in one commit: any one of them alone leaves the filesystem broken.
   `TestDirIVRace` ([tests/defaults/diriv_test.go](../tests/defaults/diriv_test.go)) is the existing
   regression test for the mkdir window.
7. **`initDir`** ([init_dir.go](../init_dir.go)) — stops writing the root diriv entirely (§0.6).
8. **`dirCache`** — `dirCacheEntry` gains the index, and `Store`/`Lookup` carry it. Without this a cache
   hit encrypts from the cached IV with no index — the banned default, on the hot path, invisibly. Note
   its two `log.Panicf` sanity checks compare `len(iv)` against a fixed `ivLen`.

**`FlagDirIV` changes meaning**: its absence used to mean "no diriv files exist", and now means "the IV
is fixed-zero rather than random". The derivation in `initFuseFrontend` still works. The CLI
help already describes the new behaviour accurately — "Disable diriv file name randomisation".

---

## 9. Key ring — the index is the position

A key-ring index is an entry's position in `KR.Keys`. `Append` returns it, `ActiveIdx()` names the last,
and the ring is append-only: pruning or reordering an entry would renumber every later one and silently
remap the objects written under them to the wrong key. The AEAD tag still fails, so the symptom would be
mass "decryption failed" rather than a clean "that key is gone".

An earlier draft carried an explicit `Idx uint16` on each entry so a pruned ring would leave a
detectable hole. Pruning is not an operation this phase supports, and the field bought a second source
of truth for something the slice already says.

Ring API grows `All()`, `Append(entry)` and `ActiveIdx()` alongside `Active()`
([keyring.go](../internal/configfile/keyring.go)).

**`KeyID` is NOT a per-entry identity — it is the FILESYSTEM's** (revised 2026-08-21, see §12.7). One KEK
serves an instance for its whole life and is minted exactly once, so every entry of a ring carries the same
`KeyID` and they differ only in `Ciphertext`. That value is also the instance's `InstanceID`: `KR` is where
a filesystem's identity lives, read back by `KeyRing.InstanceID()` on every mount.

Unlike the 2026-08-19 shape this now holds as an invariant rather than "ordinarily" — the only mint is the
first one, and every rotation names the id it already has, so no path adds a second KEK to a ring.

**It is enforced, at three layers.** `KeyRing.Validate` refuses a ring whose entries do not all name
`Keys[0].KeyID`; `rotate()` refuses a generate that comes back under a different KEK than the active
entry's; and `instanceIdentity.adopt` refuses to replace an identity the connector already holds. Every
mount after the first reads an existing ring and never generates, so `AdoptIdentity` at mount is the
only thing that gives it an identity, and without one its first rotation would arrive with an empty
`InstanceID` and mint a second KEK.

The rule to code against is still the negative one: never rely on `KeyID` to distinguish, dedupe or count
entries. And it must stay one field per entry despite the value repeating — an unwrap names the entry's own
`KeyID`, and hoisting it into a single field in `gocryptfs.conf` would put the identity somewhere it could
drift from the keys and let one bad edit orphan every entry at once.

Three consequences, all of them traps the field name invites:

- Do not key a map by `KeyID`, dedupe on it, or use it to detect that rotation produced a new key.
- Anything that must tell two entries apart compares `Ciphertext`.
- The ring index is what the on-disk markers name — a `uint16` in a file header, a diriv or a prefix,
  where a UUID will not fit and should not go. `KeyID` is only what the key service resolves.

An earlier draft (2026-08-07) said the opposite, when each generate minted its own KEK. The `-mock-kms`
mock tracks the current model: a generate with no identity mints a KEK and one with an identity wraps
under that KEK, and unwrap selects the KEK by key ID alone, as keep does
([mock_gwconnect.go](../internal/tkc/mock_gwconnect.go)). A mock that minted per generate would hide a
regression in `rotate()`'s one-KEK check.

---

## 10. Mount wiring

Replacing [mount.go](../mount.go):

```
keyRing := LoadKeyRing(...)                              // or generateInitialDataKey on a first mount
tkc.DataKey().AdoptIdentity(keyRing.InstanceID())        // the connector is built without an identity
entries := keyRing.All()
for each entry: unwrap via tkc.DataKey().UnwrapTKFSDataKey(e.KeyID, e.Ciphertext)
                -> cryptocore.New(key, backend, IVBits)   // EME + content AEAD
                -> zeroize the key
cEnc          := contentenc.New(primaryCore, aeads, DefaultBS)
nameTransform := nametransform.New(emeCiphers, ...)
```

The adoption is not decorative. `tkc.Connect` runs before the ring is loaded and therefore takes no
identity; the first mount learns one from the generate that mints it, but every later mount reads an
existing ring and never generates, and without this line it would run with an empty identity and mint a
second KEK on its first rotation.

Unwrap failures follow §0.8: fatal for the active entry and, with encrypted names, for index 0; logged
and left as a hole for any other, with `aeadForKey` reporting the missing index when something needs it.

Mount now makes N key-service round trips instead of one — fine at small N, and a reason to keep
rotation infrequent rather than chatty.

---

## 11. Error handling

Existing convention, preserved: listing paths warn and skip via `reportMitigatedCorruption`; direct
access returns EIO. A missing or malformed index is an error at the point of use, never a default.

Containment granularity for a bad diriv (§0.7):

| Operation | Result |
|---|---|
| listing that directory, or anything inside or below it | EIO |
| listing its **parent** | works — the child's name decrypts with the parent's diriv |
| `stat` on the directory itself | works, same reason |
| siblings and unrelated subtrees | unaffected |

The root diriv is the exception: every path resolves through it.

---

## 12. Rotation — mechanics, triggers, and the server side

### 12.1 Mechanics (settled, shared by every trigger)

Under the rotator's mutex: generate a new data key, check it names the ring's KEK, credit the
outgoing key's operation count, append `{KeyID, Ciphertext, CreatedAt}`, persist, build a core,
`contentenc.AddKey`, and add the EME cipher to the name set. New files and new directories then get the
new index; existing files, directories and open handles keep theirs. `CreatedAt` is keep's stamp on the
new key, returned by the generate, never the TKFS host's clock; a generate that comes back without one
fails. The first mount's entry is stamped the same way.

### 12.2 Local — op counter

`KeyRingEntry.OpCount` exists and is unused. The ticket calls for auto-rotation "well below 2³²", which
is the NIST limit for *random 96-bit* nonces — a bound that does not transfer, because this fork's nonces
are neither random nor 96-bit. **Threshold: 2³⁰ operations, configurable but not disableable.** Derived
below.

The count is kept for the *write* key only: one `atomic.Uint64` in the content key set, restarted by
`AddKey` after `rotate()` has credited the outgoing key to the ring, and accumulated on the ring's active
entry. Writes to a file created before a rotation continue under that file's own key and are deliberately
not counted — rotation is additive, so no rotation can bound them, and counting them against the active
key would measure the wrong one.

The count is checked on the heartbeat timer and once more before the filesystem is served, so a count
earlier mounts left at or past the threshold rotates before this mount writes anything, and a filesystem
only ever mounted briefly still rotates. The flush at unmount only credits.

A read-only mount sets the threshold to zero: it performs no encrypt operations, and rotating on a count
inherited from disk would write the cipherdir behind a flag that refuses to. Nothing else suppresses it.

`tkutils` `crypto.NextNonce(16)` produces `counter(8B) || random(8B)`, and the detail everything turns on
is the seed of `nonceCounter` (tkutils `crypto/encryption.go`):

```go
nonceCounter = uint64(time.Now().UnixNano())
```

Wall-clock, not zero. Two consequences:

1. **Within one process, nonce reuse is impossible** — the counter strictly increments, so no two nonces
   from one mount share their first 8 bytes whatever the random tail does. The birthday problem, which is
   what the NIST figure bounds, never applies to the intra-process case at all.
2. **Across processes, counter ranges are separated by wall-clock distance.** A mount performing *N*
   operations occupies `[T, T+N]` where `T` is its start time in nanoseconds, so two mounts can only
   collide if they start within *N* nanoseconds of each other.

A nonce repeats only if *both* halves do, so for two mounts overlapping in *k* counter values the expected
collisions are `k · 2⁻⁶⁴`, with `k ≤ N`. The worst realistic case is two NTP-synced hosts mounting the same
cipherdir at once (an NFS-shared cipherdir — gocryptfs is not a cluster filesystem, but nothing prevents
it). Even at *complete* overlap:

| N per key per mount | counter span | expected collisions per overlapping pair |
|---|---|---|
| 2²⁸ | 0.27 s | 2⁻³⁶ |
| **2³⁰** | **1.07 s** | **2⁻³⁴** |
| 2³² | 4.3 s | 2⁻³² |

At 2³⁰ that is ~4.4 TB under one key at the 4 KiB default block size, and ring growth stays a non-issue:
65536 rotations × 2³⁰ ops ≈ 281 PB. XChaCha20-Poly1305 is strictly safer (192-bit nonce = 8 counter + **16**
random) and needs no separate threshold. The counter is consumed by everything in the process, not just one
key, so a per-entry `OpCount` *undercounts* consumption — which errs safe.

**This depends on a tkutils invariant that is not enforced anywhere, and is recorded only here.** If
`nonceCounter` is ever reseeded from zero or any fixed value, every process starts at the same counter,
mounts of one filesystem overlap completely and always, and the guarantee collapses to the bare 2⁻⁶⁴
random tail — at which point the birthday bound *does* apply and 2³⁰ is far too high.

### 12.3 Local — manual

The `-ctlsock` ABI carries two commands: `{"Rotate": true}` answers with the new `KeyIdx`, and
`{"Status": true}` answers with `KeyHoles`, the ring indices this mount could not unwrap. A `-ro` mount
refuses `Rotate`, as it refuses a rekey and auto-rotation: the ring write is outside the kernel's
read-only enforcement.

### 12.4 Rekey is pulled over the heartbeat

An operator asks the gateway; the gateway records the request against that instance in keep; the instance
collects it on its next heartbeat and rotates. Nothing dials the instance, so it listens on no inbound
port for this. The first heartbeat, sent before anything is mounted (§12.10), collects one too, so a
mount shorter than one interval is still rekeyed.

The answer is one `Command` enum, `""` (carry on) or `rekey`, rather than a boolean. A command an
instance does not recognize means carry on, since the unambiguous "stop" is a 403. A `shutdown` command
for decommissioning was defined and dropped: nothing produced it, and decommissioning is what a blocklist
entry is for (§12.9). The request gains `KeyIdx`, the ring index the instance writes under, and
`KeyCreatedAt`, the active entry's `CreatedAt` — keep's own stamp on that key (§12.1). Together they do
the acknowledging. keep holds a `TKFSRekeyDirective{PastIdx, RequestedAt}`: the index the instance's
record showed when the rekey was asked for, and keep's time then. It answers `rekey` on every heartbeat
while `OutstandingFor(KeyIdx, KeyCreatedAt)` holds, which is until the instance reports an index past
`PastIdx` **and** a key keep created after `RequestedAt`. Every time in the rule is keep's, so the TKFS
host's clock decides nothing.

Any rotation after the request satisfies it, whatever triggered it — the rekey, ctlsock or the op
counter — which is correct: the operator wanted a key newer than the request, and that is what there is.
No rotation from before the request does, and each half of the rule closes a gap the other leaves. The
stamp covers a record that lags the instance: a ctlsock or op-count rotation is reported only on the next
beat, so a rekey filed in between gets a `PastIdx` below that rotation's index, and the index alone would
let it through. The index covers skew between keep nodes: the rekey may be filed on one and the generate
served by another, whose clock can put a rotation from just before the request just after it. That
rotation's index was already on the record unless the record lagged too, and missing both at once takes a
skew wider than the time between that rotation and the request. A rotation that fails after its generate never
becomes the active entry, so it is never reported. The rule is idempotent under a repeated request and
right across a remount: an instance that never rotated reports the same index and stamp, and collects
the directive again.

**The directive is its own keep object, not a field on the registry record**, because every heartbeat
overwrites that record with a blind `Put` (§12.6) and would take a directive written between two beats
with it. **keep never deletes a directive on a heartbeat.** Key creation times only move forward, so a
satisfied directive cannot become outstanding again; it stays inert until the next rekey overwrites it or
deleting the instance removes it. A heartbeat therefore only reads the directive, and there is no
read-then-write for a new rekey to race.

**Failure is the rule the op counter already set.** A rotation the key service asked for either succeeds
or ends the mount (exit 34, with no mountpoint ever attached when it came on the first heartbeat): a
filesystem told to stop using a key must not go on writing under it. The instance then stops
heartbeating, so the index an operator is watching stops moving — which is what a failure looks like
from outside, and is why the admin read exists (§12.5). `-ro` is the one exemption, and the same one
auto-rotation takes — a read-only mount may not write the key ring at all, so it logs the request, keeps
heartbeating, and leaves the directive standing for a writable mount.

**What it costs.** The admin call answers 202, not 204 — queued, not done — and the rotation lands within
one heartbeat interval. There is no urgency argument against that: rotation is additive and contains
nothing, revocation is what contains a compromised key, and revocation is paced by the same heartbeat. So
an instance cannot be rekeyed faster than it can be revoked either way.

**What it replaced** (2026-09-21) was an inbound mTLS control listener on every mount, reached by the
gateway at `POST <ControlAddress>/rekey`. Gone with it: `-control-port`, `-control-host`, exit code 32 in
its old meaning (32 is now `AlreadyMounted`, §15.1), `ControlAddress` on both the heartbeat and the
registry record, `TKFSControlRekeyPath`/`Request`,
gatehouse's whole dial path, and the SAN trap recorded in §15.1 — an instance's certificate no longer has
to carry the host it advertises, because it advertises nothing.

### 12.5 gatehouse — the caller

`PUT <versionPrefix>/tkfsdatakey/rekey/:instanceID` with `RequireAdmin`, registered from
`registerTKFSDataKeyAdminAPI`, posts to keep and answers **202** with the stored `TKFSRekeyDirective` —
whose `PastIdx` and `RequestedAt` tell the operator which index has to move and what the new key must
postdate. keep's 404 (no such instance) is answered
404; any other failure is answered 500. It
carries the audit action (`NewAction(r, "...").Start()` + `defer action.CompleteEx()`), as every TKFS
admin mutation does.

`GET <versionPrefix>/tkfsdatakey/instance/:instanceID` proxies keep's registry record, which is where that
index is read back. gatehouse exposed no instance read at all before, so without it a pulled rekey would be
unobservable from the admin plane. Beside it, also `RequireAdmin` and proxied to keep:
`GET <versionPrefix>/tkfsdatakey/instances` lists the registry, and
`DELETE <versionPrefix>/tkfsdatakey/instance/:instanceID` forgets one record along with any rekey pending
for it. Forgetting is not blocking: a mount still running registers again on its next heartbeat.

**One instance per call, named by the path** (settled 2026-08-07; moved out of the body 2026-09-22). An
earlier draft let the request name any of DN, NodeID or InstanceID and fanned out over every match, with a
per-instance results list and a guard against an empty selector being read as "the whole fleet". That was
solving a problem nobody has: rekeying is a per-instance operation, and `InstanceID` names both the
instance and the KEK its new data key is wrapped under (§12.7), so there is nothing else to select on.
Rotation is additive and takes no parameters either, so both hops are **bodyless** — there is no request
type on either, and `TKFSRekeyRequest` was deleted rather than left holding one field.

An operator provenance note rode the directive in an earlier round, composed by the gateway from the
authenticated admin DN so the instance's own log recorded who asked. It is gone, and what that costs is
worth stating: attribution now survives only in the gateway's `tkfsRekey` audit action. keep logs
`{tenant, instanceID, pastIdx}` and stores no caller, and the mount logs the rotation without saying who
asked for it. That is the same gap every other TKFS route at keep already has — the ACL, trust-set and
blocklist writes are equally unattributed — so closing it is its own change covering all of them, not a
string on this one.

### 12.6 Addressing — TKFS self-registers, keep remembers

Earlier notes said gateway push was blocked on the Phase-4 instance registry. **That is wrong.**
`model.TKFSInstance` carried `NodeID`, `DN`, `IdentityDoc`, `Status`, `FirstSeen`, `LastSeen` — and **no
address field** — and had zero references anywhere in gatehouse. The registry as modeled would not tell
the gateway where to reach an instance even once it exists.

**Instead TKFS heartbeats to the gateway, which forwards to keep.**

- TKFS sends `POST …/tkfsdatakey/heartbeat` on the existing mTLS data-key listener — the same client,
  cert and connection it already uses — carrying `{NodeID, InstanceID, KeyIdx, KeyCreatedAt}`. The DN comes from the
  verified client cert, never the body, matching how the data-key handlers already derive it
  (`tcutils.SanitizeDN(tcutils.CertificatesToClientDN(r.TLS))`). Adding the route costs one line in
  gatehouse's `registerTKFSDataKeyAPI`, one handler, and one assertion in the existing route test.
- keep records `InstanceID -> {DN, NodeID, KeyIdx, KeyCreatedAt, LastSeen}`.

**`InstanceID` is a third, unique field** — the id of the KEK keep mints on the filesystem's first
generate, recorded as the `KeyID` of its first key-ring entry and read back from `KR` on every mount. It
is *not* a config field and is *not* minted at `-init`: see §12.7 for why the identity is derived from
the key rather than invented alongside it. It is the registry key on its own. Without it two filesystems
that happen to carry the same DN and NodeID would collide onto one entry, each heartbeat overwriting the
other's index, and a rekey would be aimed at whichever wrote last. It also gives the blocklist a way to
name exactly one instance (§12.9).

`Status` (`active` / `blocked`) was **dropped from the record**. Nothing but `active` was ever written —
a blocked instance is refused before it reaches the registry — so the field was a constant dressed as
state, and a second place to read a block decision that `TKFSPolicy.Blocklist` alone is authoritative
for.

It **names the KEK**, as of the 2026-08-21 revision (§12.7): the instance is the isolation unit, its KEK
is its own, and the identity is that KEK's id rather than a separate UUID. An earlier draft excluded the
instance from key derivation altogether on the grounds that wiring a UUID in would make every existing
filesystem's key unrecoverable — true, and irrelevant in unreleased work.

What it is **not** is a per-*mount* value — it is stable across mounts, so an instance reappears as itself
rather than accumulating an entry per mount, and its ring keeps unwrapping. The honest caveat is that
`cp -a` of a cipherdir copies `KR`, so a copy shares the original's identity and therefore its keys;
distinguishing copies is not something a value stored in the copied directory can do. A copy taken
*before* the first mount is the one case that now separates cleanly: it has no identity to copy, so each
side mints its own. A rekey aimed at a shared identity therefore reaches every copy. keep judges each
heartbeat on its own report, so every copy rotates its own ring until it is past the directive, and a copy
behind the one whose index the rekey was filed against rotates once a beat until it catches up.
- The first heartbeat fires before anything is mounted (§12.10), so registration is prompt rather than
  waiting out an interval; after that it is periodic. The epic already calls for a 5-minute op-counter
  flush, so one timer serves both.
- Authorization is the same conditions as every other call (§12.9) — trusted CA, DN in the ACL on the
  gateway route, nothing blocked. The CA is checked by the listener's TLS handshake; the rest by keep, on
  the same call that records the instance (§12.7). The gateway forwards and classifies the answer.

The reported fields are `KeyIdx` and `KeyCreatedAt`, not rekey-specific ones — they are what this instance
is doing, and a rekey is only one of the things that make them change (§12.4).

Four things fall out of this:

- No address anywhere, operator-supplied or self-asserted, so no SSRF surface and nothing to dial.
- `LastSeen` is exactly the "active vs no-longer-reachable" view the plan wants from the registry, which
  is a Phase-4/5 deliverable arriving early and in the right place.
- A gateway restart self-heals within one interval, instead of leaving the admin action mysteriously
  unable to find an instance that is running fine.
- The record is the shape Phase 4 needs — it gains `IdentityDoc` rather than being replaced.

**The registry is keep-backed, and that is forced by the deployment, not chosen.** A tenant is "a cluster
of TrustedGateways (typically in an ASG behind an ELB)" (gatehouse `CLAUDE.md`, and
`documentation/md/ug_gateway.md`); the code depends on it, mutually approving ASG siblings in
`main.go`. So a TKFS instance heartbeating through the ELB lands on an arbitrary gateway while a
*different* arbitrary gateway serves the admin action that wants to rekey it. An in-memory map would be
populated on one instance, invisible to the rest, and lost on scale-in. Keep is the only
cross-gateway-visible store in this codebase besides the optional Redis credential cache. It is also
where every other object that has to be visible from any gateway already lives — the TKFS trust set
included — for exactly this reason.

**One keep object per instance, keyed by `InstanceID` — not a single registry object.** keep's existing
policy write lock is explicitly process-local and is justified by the traffic being low-contention
admin-plane writes (keep `web/tkfspolicy.go`, `tkfsPolicyWriteMu`: it serializes them "within this
process").
Heartbeats are neither low-contention nor admin-plane. Putting them into one shared object would be a
read-modify-write on every heartbeat from every instance across every keep node, with no cross-node
coordination — a lost-update generator. Per-instance objects make each heartbeat a blind `Put`: no RMW,
no lock, no contention.

The key is the `InstanceID` and nothing else. It identifies an instance on its own, and a DN or NodeID
prefix would only mean an admin had to know both to look up an instance they named by ID. The cost is that
the key is now entirely self-asserted: an authorized instance that claims another's `InstanceID` takes over
that record. Nothing authorizes off the registry — it is heartbeat-rebuilt state for the admin view and for
holding directives — so what a takeover buys is a misleading listing and a rekey collected by the wrong
instance of the same tenant, which costs that instance a ring entry.

Two properties of the data-key listener that a heartbeat route inherits, both intentional and worth
stating rather than discovering:

- The supervisor **tears the listener down when the trust set has zero CAs**
  (`tkfsDataKeyListenerSupervisor.reconcile`, gatehouse `management/tkfsdatakey.go`), so heartbeats stop
  with it. That is the fail-closed behaviour working as designed, but it means "no heartbeats" has two
  causes.
- It **restarts the listener whenever the CA set changes**, dropping in-flight connections. A
  heartbeat is cheap to retry; the client should not treat one failure as significant.

**Trust boundary.** The DN is cert-proven; `NodeID`, `InstanceID`, `KeyIdx` and `KeyCreatedAt` are
self-asserted, the same caveat the data-key handlers already carry. An authorized instance can
therefore report a key it is not on, and so satisfy a rekey it never performed. That is bounded by what it
buys: the instance already decides whether to rotate at all, so a liar gains nothing it could not have by
ignoring the directive outright.

**This was the alternative, and it is now what shipped** (2026-09-21, §12.4). Polling for a queued
rotation was recorded here as "worth revisiting if gateway→TKFS reachability turns out to be a problem",
costed at "a persisted per-instance rotation-pending flag in keep — real new state". The flag is
`TKFSRekeyDirective` and that costing held; what changed the answer was not reachability but that the
inbound listener bought nothing the heartbeat could not, and cost an open port on every mount plus a
provisioning trap (§15.1).

### 12.7 keep — one KEK per instance, and the identity derived from it

**Revised 2026-08-19, reversing the 2026-08-07 revision.** The design has now been through both answers,
so both are recorded.

The 2026-08-07 draft minted a **fresh KEK on every data-key generate**, so each ring entry had its own,
justified as "compromising one KEK exposes one data key rather than every key the filesystem has ever
used". **That is now reversed: one KEK is minted the first time an instance asks for a data key and serves
that instance for its whole life; rotation mints a new DEK under the same KEK.**

Why the reversal is right rather than merely simpler: a KEK never leaves keep. Extracting one means
reaching keep's key hierarchy, and an attacker who can do that for one KEK can do it for all of them — so
the per-entry split bought very little against any realistic threat model. Against that it cost unbounded
KEK growth (one per rotation, forever, with no delete path).

**Rotation is not KEK-compromise containment, and that has to be said out loud.** The instance's KEK
wraps every entry its ring has ever held, so a rekey mints a new *data* key under the same KEK. What
rotation bounds is how much data sits under one data key — exposure by age, and the op-counter threshold
of §12.2. The response to a suspected KEK compromise is a new instance: a fresh `-init`, whose first
generate mints a new KEK and hence a new identity — plus copying the data across. There is no
rekey-shaped answer to it.

**The identity IS the KEK's id, and the keyspace concept is gone** (simplified 2026-08-22). keep mints a
filesystem's KEK on its first generate — the one call that carries no `InstanceID` — and the id it returns
is the identity the filesystem adopts. `model.TKFSKeyspace` is deleted, along with the `kek/ks` and
`kek/own` KVS prefixes, `KekWrapScoped`, `KekUnwrapScoped`, `ensureScopedKek` and `recordKekOwner`. The
three TKFS manager methods that briefly replaced them are gone too: `ensureKek` resolves a kek by id when
given one, mints an unassociated kek when given neither id nor path, and otherwise follows the `kek/curr`
association as before — so `KekWrap` serves every service and unwrap is plain `KekUnwrap`.
`TKFSDataKeyUnwrapRequest` lost its `InstanceID` field, since `KeyID` is that same value.

Three shapes preceded it, and each one was answering a question this one dissolves. `DN + NodeID` put a
filesystem's keys behind its certificate. The `DN + NodeID + InstanceID` triple of 2026-08-19 added the
instance while keeping both. `InstanceID` alone, earlier the same week, dropped the other two — the UUID
already identified an instance, and each extra component cost something real: the DN made a re-issued
certificate or a DR restore onto a differently-named host compose a *new* keyspace owning no KEK, so the
active ring entry 403s and the filesystem does not mount; the NodeID made renaming a node do the same.

What remained after that was a self-inflicted problem: a locally minted UUID needs a
`keyspace -> KEK` record so keep can find the KEK, and maintaining that record is a read-then-write over a
store with **no compare-and-set**. Hence two records, a load-bearing write order between them, a tolerated
double-mint race, and a repair path for a `kek/ks` entry naming an owner-record-less KEK. Deriving the
identity from the KEK deletes all of it: the first call is a write-only mint to a fresh uuid path, so there
is nothing to look up and nothing to reserve. If a retry across keep hosts turns one logical call into
several, the extras are anonymous and unreferenced — the caller keeps the one id it was handed.

**Nothing replaces the ownership record.** An `IsTKFS` marker on the KEK was tried, so that the TKFS
routes would refuse a general KEK and the general unwrap would refuse a TKFS one. It was dropped: with
the identity self-asserted, a caller who can name a KEK id can name any of them, so the marker refused
nothing an attacker had to work for. What it did cost was a field on a shared struct and a pair of
single-purpose manager methods.

The consequence, stated once: `tcv.KekUnwrap`'s general branch is reached with an MCSE permission
satisfied for some *other* object and does not bind `WrapperID` to it, so an MCSE-authorized caller in the
tenant can unwrap a TKFS ring entry by presenting its `KeyID`. That predates this phase and is unchanged
by it. Fixing it means binding `WrapperID` to the permitted object, which is the MCSE path's problem to
solve, not a TKFS marker's.

**Authorization moved into keep** (2026-08-22). `tcv.KekWrap` and `tcv.KekUnwrap` no longer *skip* the
permission check for `ServiceTKFS` — they run a TKFS-specific one (`tcv.TKFSPermissionCheck`): the DN must be
in the tenant's ACL and no blocklist entry may name the DN, the NodeID or the instance. It reads the
existing `Creds *Authorization`, using `UserDN` and carrying the NodeID in `Source`; the instance is the
KEK id already on the request.

Three things follow. keep's own `web/tenantdatakey.go` now goes through the same `tcv` calls, so a
`-search` mount is subject to the policy — **it had no such check at all before**, which was the one real
hole in the design. (Amended 2026-09-22: to the *blocklist*, not the ACL — see §12.9.) The gateway stops deciding per call, so a DN revoked since its last
policy refresh is refused by keep rather than admitted by a stale snapshot. And there is one
implementation of the decision instead of one-and-a-gap.

The DN is asserted by the caller: the gateway takes it from the instance's verified client certificate,
keep's search route from its own. That is the trust keep already extends to a gateway for every other
permission. The gateway sends TKFS KEK calls to its own tenant's keep only: `oec` never retries them at
an S2S peer, so TKFS key material stays in the tenant, though it still retries an unavailable keep across
the local hosts. **The gateway now holds no TKFS policy decision at all.** Its listener filter is
`RequireAny` (the client-CA pool is already the operator TKFS CA set), and the heartbeat is a pass-through too:
keep's `PUT /tkfsinstance` authorizes it on the same call that records the instance, via the same
`tcv.TKFSPermissionCheck` the KEK routes use.

**So the trust set became its own object** (`model.TKFSTrustedCAs` at keep's `tkfsca`, served on
`/tkfscas`), leaving `TKFSPolicy` as `{ACL, Blocklist}`. The gateway fetches only the trust set and no
longer receives the tenant's ACL or blocklist at all. Bundling them had been justified by keeping "the
TLS trust pool from drifting apart from the ACL", which only meant something while one component
enforced both; now the gateway's TLS config enforces condition 1 and keep enforces 2 and 3. The real
gain is that the two no longer share a failure — see the fourth unmount path in §15.1, which this
closes.

**`-search` heartbeats too** (2026-09-21). keep serves `POST /keepsvc/tenantdatakey/heartbeat` beside
generate and unwrap, running the same `tcv.TKFSPermissionCheck` and the same registry upsert that
`PUT /tkfsinstance` does, on the same 403-is-fatal rule. A search mount is therefore authorized,
registered, paced and revoked exactly as a gateway-proxied one, and since a missing route fails the mount
(§12.10), a keep too old to serve it refuses `-search` rather than running it with no revocation.

That makes the registry upsert the channel that revokes a mounted instance, and leaves the gateway one
job on a heartbeat: **forward keep's answer, whatever it is.** A 403 reaches the instance as revocation
and unmounts it at once; every other failure is forwarded as a failure and spends one of its three
strikes.

**A heartbeat keep did not record is not a heartbeat** (2026-09-22). An earlier round answered 200 on a
registry failure, reasoning that "cannot authorize" and "cannot persist" are different claims and only
the first should unmount anything (§15.1). The distinction is real but the conclusion was wrong: the
record *is* how the instance is reachable by revocation — an admin blocking it acts on a registry the
mount no longer appears live in, and a rekey directive cannot be satisfied by a report that never landed.
A mount serving on an unrecorded heartbeat is a mount nobody can stop. So keep returns the error, the
gateway forwards it as **502**, and the three-strike budget absorbs the transient case. The cost is
stated below: a keep outage past the window now unmounts the tenant, which is the third fleet-wide path
§15.1 had closed and has deliberately reopened.

**What this costs, stated plainly.** Key isolation is soft: the identity is self-asserted and lives in the
same `gocryptfs.conf` as the `Ciphertext`, so within one tenant any ACL'd caller holding another
instance's config can present that identity. The tenant, from the client cert on both routes, is the only
hard boundary; per-instance separation is a partition inside it. And a KEK can never be replaced — one
derived slot per instance, no pointer to move — so the "new instance, not a rekey" answer above is now
structural rather than policy.

Two smaller consequences. An instance has **no identity until its first successful generate**, so it
cannot be pre-registered or pre-blocked by `InstanceID` (DN and NodeID still apply, and a mint is gated on
those alone — there is no instance yet for a block to name). And the KEK id becomes operator-facing: it
appears in admin listings, blocklist entries and rekey requests. No new exposure, since `KeyID` was
already in `KR` next to the ciphertext, but it means key identifiers get pasted into tickets.

**The `KekRotate` hazard is closed outright rather than avoided.** `KekRotate` is reachable on the
gateway-facing object API with a caller-supplied `Path` and no check on it (keep `web/object.go` →
`tcv.ObjectManagementDAO.KekRotate`), and it writes `kek/curr`. Sharing that namespace was the reason
`kek/ks` existed as a separate prefix. A TKFS KEK is now resolved by id directly, so there is no pointer
to move even for a rotate aimed at an instance's identity — pinned by
`TestKekRotateCannotMoveAnInstanceKek`.

Nothing here changes shared semantics for non-TKFS callers: `KekWrap` behaves as before whenever a
`Path` is given, and `KekUnwrap`, `KekGet` and `KekRotate` are untouched.

**keep's own data-key route.** `web/tenantdatakey.go` serves TrustedSearch mounts, which talk to keep
directly with no gateway in front. It mints on an empty `InstanceID` and rotates otherwise, exactly as the
gateway path does, so the two reach the same KEK for the same instance and a filesystem is not locked to
the route that created it. The other side of it: this route, authenticated by tenant cert and token alone,
can reach a gateway-managed instance's KEK by asserting its `InstanceID`. It also applies **no ACL or
blocklist check at all** — blocking an instance does nothing to a `-search` mount — which is the gap
Part B (moving authorization into keep) exists to close, and did: see the dated amendment above, which
also gave the route family a heartbeat.

**Four properties that changed, or that the reversal makes worth stating.**

*A KEK now performs many wraps instead of one.* `kek.Wrap` is AES-256-GCM with a nonce from
`crypto.NextNonce`: an 8-byte process-global counter seeded from `time.Now().UnixNano()` plus 4 random
bytes. Within a keep process the counter makes repeats impossible; across processes and restarts
uniqueness is probabilistic. A GCM nonce collision under one KEK would leak the XOR of two DEKs and the
GHASH key. Volumes make this a non-issue — one wrap per rotation, a single-digit number over a
filesystem's life — but the property moved from *impossible* to *overwhelmingly improbable* and should be
stated rather than assumed. Anything that ever wraps at volume under one KEK needs to revisit it.

*Nothing cryptographically binds a wrapped DEK to an instance.* `kek.Wrap` passes a constant as
associated data. There is no longer a KVS record to subvert either — the binding is that the id names the
KEK — so what remains is that whoever can write keep's store can rewrite key material outright, which is
strictly worse than anything this would defend against. Closing it means adding identity-as-AD to the
`kek.Kek` interface, which MCSE also uses, and invalidating every existing ciphertext: its own versioned
change, not a rider on this one.

*Editing the identity bricks the filesystem.* It is the id of the KEK, so a different value names a
different KEK or none, and every unwrap is refused. It is no longer a `gocryptfs.conf` field an operator
can reach — it is the `KeyID` in `KR`, sitting next to the ciphertext it belongs to, which is a much
better place for it to be. This is exactly what an operator reaches
for after cloning a VM image that copied a cipherdir and produced duplicate registry entries — and the
answer there is a fresh `-init` for the clone, not a new UUID. Stated on the field itself
(`KeyRingEntry.KeyID`, [keyring.go](../internal/configfile/keyring.go)) because that is where someone
about to do it is looking.

*Two constraints the simplification removed, recorded because they were previously documented as
permanent.* Route stickiness is gone: the gateway route and keep's direct route composed different
keyspaces while the DN was a component, so flipping a filesystem between `-search` and the gateway got it
a second KEK and refused every earlier entry. Both now name the KEK by the same id, so the two agree. And
shared storage no longer assumes a shared DN: hosts mounting one cipherdir in turn under *different* cert
DNs used to compose different keyspaces and each append entries the other could not unwrap. They now share
the identity, because they share the `KR` that carries it. (Mounting it on two hosts at once is still
unsupported; see the one-mount rule in §15.1.) What replaces both is the soft-isolation cost
above — the same property that makes the routes agree makes an asserted identity sufficient to reach a
KEK.

**Two operational consequences, both settled.**

*KEKs are retained permanently, by policy rather than by mechanism.* keep has no KEK-delete path anywhere,
so retention holds today; but nothing indexes which KEKs a ring depends on, and the ownership record says
who owns a KEK, not whether a ring still needs it. Decided: keep them all regardless, so nothing needs
building. Anything that ever adds KEK garbage collection or tenant cleanup must treat this as a hard
constraint — deleting a referenced KEK is unrecoverable and nothing in the store will warn it. Per-instance
KEKs make this far cheaper than the per-entry model did: the count tracks instances, not rotations.

*The KEK usage metric.* Category 16 counts the `kek/key/` prefix — every KEK — and was named `MCSEKek`, so
it had begun counting TKFS KEKs under an MCSE name. Resolved by making it say what it counts: **one `Kek`
series, the total across every service that mints them.** A split was tried first (a `TKFSKek` category
counting the then-existing `kek/own/` prefix, subtracted from `MCSEKek`) and rejected as more machinery
than the question deserves: it could only ever be *derived*, so the MCSE half would have been
total-minus-TKFS, and a KEK whose ownership record was never written would have been miscategorised
forever. The total was the only figure that was always right, and it is the one kept. The numeric value is unchanged, so the stored series continues; what it
means is now what it always measured. The services still do not count alike — MCSE mints one per endpoint,
TKFS one per instance — so a tenant running both sees a series that moves for two reasons. That is the
price of one number, and it is the right price.

One reading note for whoever watches that series: a TKFS tenant's KEK count **drops sharply** at this
deploy, from one per data key to one per instance. Anyone treating it as a TKFS activity signal gets a
cliff; the count they want is `TBHosts`, which counts connections.

### 12.8 Ring growth — bounded, no rate limiting

The ring only grows, since nothing is re-encrypted, and every mount unwraps every entry. That is fine:
`keyIdx` is a `uint16`, so the format tops out at 65536 entries, and realistic use is under ten keys.
Nothing enforces that ceiling — a guard against a ring three orders of magnitude past any real one is a
test nobody can write and an overflow comparison to get wrong. Mount cost is O(N) key-service round trips
with a single-digit N.

**No rate limiting needed on the rekey endpoint.** A retrying caller now costs nothing at all: the
directive is one object per instance, so a repeat overwrites rather than queues (§12.4). It never cost
extra KEKs either: since §12.7 a rotation reuses the instance's KEK, so the only KEKs that leak are a
retried mint's extras and one minted by a first mount that dies before persisting its ring. (For the
record, gatehouse has no rate-limiting or idempotency convention in `management/` today, so adding one
would have been novel machinery for a non-problem.)

### 12.9 Authorization model — three conditions, no per-operation permissions

For a TKFS instance to make a successful call, exactly three things must be true:

1. The CA that signed its certificate is in the trusted set.
2. Its DN is in the ACL — **gateway route only**, see below.
3. Neither its DN, nor its NodeID, nor its InstanceID is recorded as blocked.

That is the whole model. **Rekey is not a separate permission**, and neither is anything else. On the
gateway route condition 1 is the operator's `TKFSTrustedCAs`, enforced by the data-key listener's TLS
handshake; a `-search` mount presents a certificate keep itself provisioned, so there it is keep's own
TLS trust. keep decides 2 and 3 on every call.

**Condition 2 does not apply to `-search`** (2026-09-22). The ACL vets a DN that *a gateway asserts for a
third party*; a TrustedSearch mount reaches keep directly, presenting a certificate keep itself
provisioned plus that tenant's token, so the tenant is established before the policy is consulted and the
DN is machine-minted per node rather than anything an operator could have curated. Requiring one to be
added by hand made a mount's success depend on an operator transcribing a name nobody chose.

keep therefore takes the route as an argument (`tcv.TKFSRoute`, `TKFSGateway` / `TKFSSearch`) rather than
reading it off the request: it is a fact about which door the call arrived at, and anything on the wire
could be forged by a caller wanting the looser check. `TKFSGateway` is the zero value and the `switch`
falls to it by `default`, so a call site that forgets the argument gets the strict check. Conditions 1
and 3 are unchanged on both routes — the blocklist is how a mounted filesystem is revoked, and dropping
it for search would have removed the point of the heartbeat.

**This retired the per-operation bitmask.** `TKFSDataKeyPermission` (generate=1, unwrap=2) shipped in
Phase 1 and was enforced by gatehouse's `RequireTKFSDataKeyOp` on each data-key route; both are gone
across tkutils, keep and gatehouse, and the ACL is a set of DNs. The one configuration the bitmask could
express that membership cannot is an instance permitted to unwrap but not to generate, i.e. read an
existing filesystem without being able to create or rotate a key — given up deliberately (§15).

**The blocklist matches on whichever fields an entry specifies**, and an entry blocks a request when
every field it names matches:

| Block entry | Effect |
|---|---|
| `{DN: cn=foo}` | every request from `cn=foo`, whatever its NodeID or InstanceID |
| `{DN: cn=foo, NodeID: bar}` | only instances that are `cn=foo` **and** NodeID `bar` |
| `{InstanceID: <uuid>}` | exactly one instance, regardless of its DN or NodeID |

It lives beside the ACL in the keep-backed `TKFSPolicy`, which keep reads directly on every call, so an
entry takes effect on the next one rather than after a gateway refresh. It is the *only* place a block
decision is
recorded — the registry's `InstanceStatus` field was dropped rather than kept as a second, non-
authoritative copy (§12.6).

**Enforceability differs by field, and the difference is not cosmetic.** The DN is cert-proven, so a DN
block is *hard* — a blocked DN cannot present itself as anything else without a different certificate.
NodeID and InstanceID are self-asserted in the request body, so blocks on them are *soft*: an instance
that wants to evade one can simply send different values, and it will still pass conditions 1 and 2.
Per-instance isolation is soft in the same way and for the same reason (§12.7), and it is the right trade for
what blocking is actually for — decommissioning an instance an operator controls, not defending against
one that has been compromised. Against a compromised instance the levers that hold are the ones keyed on
its certificate: a blocklist entry naming the DN, removing the DN from the ACL, and removing its CA from
the trust set. The last two apply on the gateway route only, so a `-search` mount answers to the DN
block alone. A CA removal also acts more slowly than the other two: it fails the TLS handshake rather
than drawing a 403, so a mounted instance goes down on its third failed heartbeat (§12.10).

---

### 12.10 Losing the heartbeat kills the mount

Three consecutive failed heartbeats and the filesystem unmounts itself. A definitive rejection kills it
immediately, without waiting out the count.

| Heartbeat outcome | Effect |
|---|---|
| `200` | reset the failure counter, and carry out a `rekey` it brought back (§12.4) |
| transport error, TLS failure, 5xx | increment; **third consecutive failure → die** |
| `403` | **die now** — authorization is gone, not unavailable |
| `404` / `501` | **die now** — a key service without the route cannot revoke this instance |

A `rekey` that fails to rotate ends the mount too, at exit 34 rather than 33: that is the op
counter's succeeds-or-dies rule (§12.2), and the same reasoning reaches it.

The first heartbeat goes out **before `initGoFuse`**, so a refusal, a missing route or an unreachable key
service fails the mount with no mountpoint ever attached — there is no failure budget before one exists.
A `rekey` it brings back is carried out there too, before anything is served, and so is a rotation the
persisted op count is already due; `-ro` does neither. Everything below describes the mounted case.

`403` is what blocking already produces, at no extra cost: keep's `TKFSPermissionCheck` refuses a blocked
DN, NodeID or InstanceID, and on the gateway route a DN no longer in the ACL, and the gateway forwards
that refusal as a `403`. Removing the CA does *not* land there: the listener's TLS handshake fails before
any request is made, so it counts as a transport failure and the instance goes down on the third.

**When it dies depends on why; how it dies does not.** A refusal ends the mount on the heartbeat that
carries it. Losing contact is survivable twice, and the third consecutive failure ends it too. Both then
take the same path: attempt a clean unmount, and if the mountpoint is busy give it a short grace period
(`forcefulUnmountGrace`, 10s), try once more, and exit **33** regardless — leaving, at worst, a dead
mountpoint whose every operation fails. It does **not** zeroize: the filesystem may still be answering
requests, so a wipe would race them, and the process exit drops the memory regardless. A stale mountpoint
is an operator cleanup problem; a filesystem still serving after the key service can no longer vouch for
it is a security failure.

**There used to be a second, gentle path, and it went in two steps** (2026-09-25). Lost contact once
unmounted the way `idleMonitor` does — try, and on a busy mountpoint log and retry at the next tick, never
escalating — and a heartbeat that succeeded meanwhile called the whole thing off. The abort was defensible
(revocation arrives as a `403` and was never abortable, so it could not keep a blocked instance alive), but
it made the outcome depend on whether anyone happened to have a file open: an idle mount went down on the
first attempt and stayed down, a busy one survived if the gateway came back. The abort went first. That
left the retry, and the retry was the same defect in another form — a busy mount that had lost contact
went on *serving*, every five minutes failing to unmount, for as long as someone kept a shell in it,
with no bound at all. It also exited **0** once it finally did unmount, because it never set
`fatalExitCode`, so a supervisor could not tell "lost its key service" from an operator's `fusermount -u`.
With nothing left to distinguish them, the two paths are now one, the enum is a boolean, and there is no
latch: the decision to stop ends the process.

**The window is interval × 3** — fifteen minutes at the hardcoded five-minute heartbeat, plus the grace
period. That is the bound on how long a mount keeps serving once its key service stops vouching for it,
busy or not, and it is the number to argue about if either property matters more than the other.

**Two consequences that need to be understood before this ships:**

- **A gateway *or keep* outage unmounts every filesystem fleet-wide.** keep joined this list on
  2026-09-22, when a heartbeat it cannot record became a failed heartbeat (§12.7), and *every* became
  accurate on 2026-09-25, when the gentle path was removed (§12.10): a busy mount goes down within the
  same window as an idle one, at worst leaving a dead mountpoint. Filesystem availability is gated on
  key-service availability, with no exception for having a file open. The ELB masks single-instance failures and ASG replacement, not a real
  outage. This is the deliberate trade for bounded revocation, and it is a documented operational
  property. The interval is deliberately not configurable: it *is* the revocation window.
- **Removing the last trusted CA kills every instance in the tenant.** The data-key listener is torn down
  when the trust set has zero CAs (§12.6). With heartbeat-death
  in play, that fail-closed teardown now means every heartbeat in the tenant fails and every filesystem
  unmounts within the window. An admin removing what looks like a stale CA gets a fleet-wide outage. This
  is an emergent interaction between two individually reasonable decisions; at minimum the admin CA-removal
  path should warn when it would empty the set.

## 13. Testing

**Unit.** Distinct derived keys per entry; `aeadForKey` range behaviour including a hole from a failed
unwrap; `AddKey` snapshot swap under `-race` with concurrent readers; header round-trip at a non-zero
`KeyIdx`; diriv read/write at 18 bytes in all three modes; the shared-`KeyID`, distinct-`Ciphertext` ring
shape.

Added with the one-KEK enforcement and the single op counter: `Validate` rejecting a ring that names two
KEKs, and `LoadKeyRing` doing so with `LoadConf`; `instanceIdentity.adopt` being idempotent on the same
id, a no-op on the empty one, and an error on a conflicting one; the content op counter restarting at
`AddKey` and ignoring writes under a superseded index; `AddOpCount` crediting only the active entry and
refusing an empty ring; and `Wipe` under `-race` with concurrent readers, on both the content and the
name side, which had no coverage at all.

The heartbeat monitor runs against a fake heartbeater, server and exit (`heartbeat_test.go`): a refusal
unmounts and exits 33, a `rekey` rotates and reports the new index at once (a refusal on that report still exits 33), a failed one exits 34, `-ro`
leaves the directive pending, an unknown command carries on, and the pre-mount heartbeat refuses on
anything but an answer and carries out a `rekey` before there is a mount. Every beat reports the active
entry's index with keep's stamp for it, and a rotation by any trigger moves both. The rotation's and the
first mount's ring entries store keep's stamp rather than the local clock, and both connectors refuse a
generate that carries none. `flushOpCounts` rotates at the threshold and on a count inherited from disk
(`rotate_test.go`).

**Integration** in `tests/tkfs_kek`: write, rotate, write; old and new files both read; symlinks and
xattrs written before the rotation still resolve; an inode's first xattr after a rotation takes the new
index while an older inode keeps its own, and an encrypted xattr name with no marker is refused; a
directory created after rotation uses the new name key while an older sibling still resolves; remount
rebuilds every key and rotates under the same KEK; a mount shorter than one heartbeat interval still
credits what it wrote, its teardown flush never rotates, and the next mount rotates before serving once
the count is past the threshold; a hole serves everything else and is named by ctlsock `Status`, while
one in the active entry or (with encrypted names) index 0 is fatal; a first mount whose ring write fails
leaves the root diriv and no ring, and the retry mounts. The `-deterministic-names`
rotation test carries a positive control — two directories keyed the same must still produce identical
names — without which it would pass if the mode merely stopped being deterministic.

**Upstream suites restored.** A 2021 fork commit renamed the test files of `tests/cli`, `tests/matrix`
and `tests/sharedstorage` to `*_test_linux.go`, which `go test` never compiles, so their 35 tests had
not run since. `tests/cli/cli_test.go` and `tests/matrix/concurrency_test.go` are back under upstream's
names. Two of their tests this phase broke: `TestInitFilePerms` checked a root diriv `-init` no longer
writes (§0.6), and `TestOrphanedSocket`'s second mount now exits 32 on the one-mount lock before it
reaches the socket. Tests of features the fork removed (`-passwd`, `-reverse`, password prompts) are
deleted, and so is `tests/sharedstorage`: both its tests mount one cipherdir twice, which the one-mount
rule (§15.1) refuses.

**Known breakage to fix in the same change:**
- `tests/xattr` hand-writes a 16-byte diriv over the one `-init` produced (in its `TestMain`,
  [xattr_integration_test.go](../tests/xattr/xattr_integration_test.go)) — the whole suite fails
  at `TestMain` once the length check moves. *Corrected during implementation:* lengthening it to 18 is
  not enough, the write has to go entirely. With the root diriv now created by the first mount (§0.6),
  any pre-mount diriv collides with the `O_EXCL` create. It was vestigial anyway — its comment claims it
  makes filenames deterministic, but under the KEK model the EME key is gateway-random per filesystem, so
  they never were.
- `TestDeterministicNames` globs `cDir/*/*` and requires exactly 2 matches; with a diriv in each
  directory it sees 4.

Rebuild the binary before running anything under `tests/` — they exec a prebuilt `../../gocryptfs`.

**A cheap completeness check when the change is done:** grep for `WriteKeyIdx`. Three decrypt call
sites pass it as the *read* key today — one in `decryptSymlinkTarget` and two in `decryptXattrValue`
([root_node.go](../internal/fusefrontend/root_node.go)). That is literally the banned
default on a read path, and closing it is exactly what markers 2 and 3 are for. Afterwards, any
remaining occurrence on a read path is a defaulting bug.

---

## 14. What this does not close

**Rotation is forward-only.** Nothing is re-encrypted, so:

- A directory keeps the name key it was created with. Files created in it *after* a rotation still get
  names under the old key. Only new directories get the new one.
- The root directory therefore never rotates its names, since it is created once.
- Old files keep their content key until rewritten.
- An inode keeps the xattr-name key it was first given (§0.4). Only inodes that get their first xattr after
  a rotation use the new one.

For content that is the intended behaviour. For **names after a compromise** it is a real gap: an
attacker with an old name key keeps reading new filenames in every directory that predates the
rotation, including the root.

Closing it needs a re-encryption pass — walking the tree and renaming every entry, rewriting each
long-name pair. The per-directory index makes that **resumable and crash-safe**: each directory
advertises which key its names are under, so the pass converts one directory at a time and an interrupted
run leaves a fully readable, half-converted filesystem. That is a separate feature ("rekey the
filesystem"), not part of this phase, and the ticket should say so rather than let "rotation" be read as
full recovery.

---

## 15. Open items

All items this document opened have been resolved. Recorded here with the resolution, because several
were decided on reasoning that is not recoverable from the code.

- **Op-counter threshold (§12.2) — resolved: 2³⁰, configurable but not disableable; only `-ro` suppresses
  it.** Derived in §12.2 from the
  actual nonce construction. The NIST 2³² figure never applied.
- **Heartbeat interval — resolved: 5 minutes, hardcoded**, sharing the op-counter flush timer. It *is*
  the revocation window (§12.10), which is not a knob.
  Failure threshold 3, also hardcoded. That makes the revocation window 15 minutes.
- **Admin CA-removal — resolved: warn, do not refuse.** An operator must still be able to empty the set
  deliberately; the hazard is doing it unknowingly.
- **keep's ownership index (§12.7) — resolved: built, then deleted, and the deletion is the answer.** It
  was specified as insurance against a misdirected `KekRotate`, and survived two design reversals as the
  only way to resolve a KEK without stranding entries wrapped under a superseded one. Deriving the identity
  from the KEK removed the question it answered: there is no record saying which KEK an instance uses, so
  none to authorize off or to fall behind. Nothing replaced it: what authorizes a TKFS call is the
  tenant's TKFS policy, checked in keep (§12.7).
- **§12.9 retiring `TKFSDataKeyPermission` — resolved: yes, the whole bitmask goes**, not just a rekey bit.
  The configuration this gives up is "unwrap but not generate" — an instance allowed to read an existing
  filesystem but not to create or rotate a key. Accepted.
- **tkutils changes — done.** `TKFSHeartbeatRequest`/`Response`, the rekey types in `model/tkfscontrol.go`,
  `TKFSBlockEntry` + `Blocklist` with a single `Allows`, `ACL` as `map[string]struct{}`,
  `TKFSInstance` gaining `InstanceID`/`KeyIdx`/`KeyCreatedAt`, `InstanceID` on the generate request, empty
  only on the minting call, and keep's `CreatedAt` on the generate response. Unwrap names the instance by its `KeyID` (§15.1).
  All three consumers pin the tkutils Phase-3 branch by pseudo-version until it merges and is tagged.
- **`InstanceID` in `configfile` — reversed.** It was a config field `Create` minted and `Validate`
  required; it is now the `KeyID` in `KR`, and `ConfFile.Validate` deliberately does *not* require one
  (§12.7). `KeyRing.InstanceID()` reads it, and `initFuseFrontend` hands it to the connector with
  `AdoptIdentity` once the ring is loaded — `tkc.Connect` runs before that and takes no identity.
- **Docs** — `file-format.md` and `MANPAGE.md` updated alongside the code.

### 15.1 Discovered during implementation

Things that were not visible from code reading and change the picture rather than merely correcting it.

- **The shutdown path wiped the keys while the filesystem was still serving.** `shutdownNow` reached its
  wipe after both unmount attempts had failed — i.e. with a live mountpoint attached — and a panic racing
  the `os.Exit` would replace the exit code with 2 and a stack trace, losing the operator the reason
  the mount died. It no longer wipes at all: the exit drops the memory either way.
- **The op counter was only ever flushed on the shared timer**, so a mount shorter than one interval
  contributed nothing to the budget it spent. There is now a credit-only flush in `doMount`'s teardown and
  on the SIGTERM path, which `os.Exit`s past every defer and is how a supervisor stops a mount. Crediting
  was not enough on its own: a filesystem only ever mounted briefly never reached a timer tick to rotate
  on, so a count past the threshold now rotates before the next mount serves.

- **A keep outage is a third path to a fleet-wide unmount — closed once, then deliberately reopened.**
  The first gatehouse implementation returned 500 when a heartbeat authorized but its registry write
  failed, which counts toward the three-strike budget. That was reverted on the argument that "cannot
  authorize" and "cannot persist" are different claims, and that a policy snapshot already up to a
  refresh interval stale on the happy path is no less valid because a write failed. **Reinstated
  2026-09-22** (§12.7): the argument is sound about the *authorization* and beside the point about the
  *record*. Revocation acts through the registry, so a mount whose heartbeats are not landing is one an
  admin cannot block — answering 200 buys availability by making the instance unstoppable, which is the
  opposite of what the heartbeat is for. Availability under a keep outage is now bounded the same way
  availability under a gateway outage always was.

  An explicit staleness bound (past ~30 refresh intervals the heartbeat returns **503**) was built for
  the residue and then removed once keep owned the data-key decision: a gateway partitioned from keep can
  no longer grant anything that matters, so the bound only converted a keep outage into a fleet unmount.
  The cost is that a *revocation* also cannot reach a partitioned gateway, and its instances keep
  heartbeating until it recovers.

  The heartbeat then became a pass-through as well, which merges the two operations into a single keep
  call, so the rule survives as a status test rather than a separation: keep's `403` propagates as
  revocation, and any other keep failure is forwarded as a `502` and spends a strike (§12.7).
- **`FirstSeen` costs a read, and cannot not.** keep's KVS RPC surface has no conditional write and no
  compare-and-swap, so preserving `FirstSeen` across a blind `Put` requires reading first. This is *not*
  the hazard per-instance objects were chosen to avoid: the read is of the instance's own disjoint key,
  and concurrent heartbeats from one instance write an identical value, so no update can be lost. It costs
  two round trips per heartbeat at a 5-minute interval.
- **A policy keep cannot decode fails closed, and that is the end of the story.** `encoding/json` retains
  what it decoded before an `UnmarshalTypeError`, so a partial policy would look valid and the granular
  handlers would write it back over the original. keep therefore 500s on GET and on every mutation rather
  than hand back a policy it only half read. A tenant in that state stays stuck.

  **There is deliberately no recovery route.** A whole-object `PUT` was built for one — the only handler
  that does not read first, and so the only thing that could overwrite an undecodable object — and then
  removed: the policy is mutated a field at a time, and a whole-object write is a request that can
  replace the trusted CAs and the ACL together while naming neither. It also clobbered by construction
  (no ETag, no If-Match, so a GET-edit-PUT silently discarded a concurrent admin's change) — unfixable,
  because not reading first was exactly what made it a recovery route.

  What made recovery look necessary was a stored *Phase-1* policy, whose ACL was a permission number per
  DN where the field is now a set. This is unreleased work in progress, so there are no such policies to
  migrate and no compatibility to keep. What remains is corruption, which is not a case worth carrying a
  route that can flatten a tenant's authorization in one request.

- **Failing closed put a fourth path to a tenant-wide unmount on the board, and splitting the object is
  what took it off.** Chain: a tenant's stored policy does not decode → keep 500s on GET → a freshly
  started gateway caches the zero-value policy (a *running* one is unaffected; its cache is left alone on
  a failed refresh) → zero trusted CAs → the supervisor never starts the data-key listener → every
  heartbeat in the tenant fails → everything unmounts within the window.

  What made that chain possible was one object carrying both halves: a fault anywhere in it took the CA
  set down too. `TKFSTrustedCAs` is now separate (§12.7), so an undecodable ACL costs authorization
  decisions — which fail closed one DN at a time — and cannot reach the listener. The original
  mitigation still holds for each object independently: both are only ever written as a re-marshal of
  their typed form, so nothing the admin routes store can be undecodable in turn.

- **A field that is present but optional is worse than an absent one.** `InstanceID` was added to the
  generate and unwrap requests specifically so an InstanceID blocklist entry would be enforceable there,
  but the handlers accepted it empty. Since `TKFSBlockEntry.Matches` cannot fire on an unset field, an
  `{InstanceID: …}` block was **inert on exactly the two routes that touch key material** while appearing
  covered. As built, unwrap has no `InstanceID` field: its `KeyID` is the identity, and keep matches the
  blocklist against that. Generate carries it on every call but the mint, which has no instance yet for
  a block to name (§12.7). The heartbeat requires it, rejected before authorization like `NodeID`. The
  general rule: a self-asserted field a blocklist can name must be present wherever there is an instance
  for it to name.
- **The index alone could not tell a rotation after a rekey from one before it.** `PastIdx` is whatever
  the instance's record showed when the rekey was filed, and after a ctlsock or op-count rotation the
  record lags the instance until the next beat. A rekey filed in that window was satisfied by the
  rotation it followed. keep now stamps every data key it generates, the ring stores the stamp as
  `CreatedAt`, the heartbeat reports it as `KeyCreatedAt`, and a directive stays outstanding until both
  the index and the stamp are past it (§12.4). With a satisfied directive unable to become outstanding
  again, keep stopped deleting it on the heartbeat, which also removed the race between that delete and a
  new rekey.
- **keep's test suite is not race-clean at baseline** — 84 data-race warnings at `b5406793`, in packages
  this phase never touches. `-race` is not currently a usable signal there.

- **A control listener needed a matching SAN, and that trap is gone** (2026-09-21). While the gateway
  dialed instances it pinned `ServerName` to the host half of the self-asserted `ControlAddress`, so an
  instance's certificate had to carry the host it reported as a SAN; one that omitted it heartbeated and
  authorized perfectly normally and failed only when an administrator tried to rekey it — a certificate
  problem discovered during a security action. §12.4 removed the dial, and with it the requirement.

- **A key service without the heartbeat route does not get a mount.** An earlier draft excluded 404 and 501
  from the death budget so that deploying this gocryptfs against an older gateway would not unmount a
  fleet on upgrade ordering. That trades the control for availability silently: such a mount runs with
  revocation off and only a log line says so. The first heartbeat is now sent *before* `initGoFuse`, so a
  gateway that cannot answer one fails the mount outright with no mountpoint attached, and the route
  disappearing under a running mount ends it the way a refusal does. Upgrade ordering becomes a
  deployment requirement rather than a silent security downgrade.

- **Existing development cipherdirs stop mounting**, and for a different reason than first recorded. The
  original break was `Validate` requiring a new `InstanceID` config field. That field is gone, but the KEK
  model changed underneath: a ring written before this phase names a KEK minted under the old scoped path,
  which no longer resolves. Re-`init` and copy the data across; consistent with §0.9.

- **A second mount of a mounted filesystem is refused.** Two writers that cannot see each other both append
  at the same index and the ring is rewritten whole, so the loser keeps stamping an index whose key is in no
  ring; two racing first mounts each generate, and one key ends up in no ring at all. Every mount holds an
  exclusive `flock` on the key ring's directory for the life of the process (the ring itself is replaced by
  rename), taken before anything a second mount would collide on, so that mount exits 32 (`AlreadyMounted`)
  saying the filesystem is already mounted. It waits up to a second first, because an unmounted filesystem's
  process exits a moment after `fusermount -u` returns. Within the process the rotator's mutex orders ring
  writes. Earlier rounds tried clobber detection and a `gocryptfs.conf` flock that serialized competing
  mounts instead of refusing one; both are gone. `flock` is advisory, and on shared storage it may not span
  hosts or may be refused outright; a refused lock only warns, and that mount proceeds unguarded.
  `-sharedstorage`, an upstream flag about stat caching and hard links, does not lift the rule.

- **A transient unwrap failure at mount became a permanent hole.** `buildKeySets` treated every non-active
  unwrap error identically — warn, `continue`, nil cipher — and nothing retries, because it is the only
  unwrap call site. §0.8 chose that containment for a *revoked* key, which is a decision; the code could
  not tell revocation from a blip, though `tkc.ErrDenied` already exists for exactly that distinction and
  `heartbeat.go` already uses it. A mount makes one round trip per retained entry, so a long ring gets
  many chances to hit one. The mount would report success and exit 0 while serving a permanently truncated
  view of its own data. Fixed by retrying transient failures and reserving the immediate hole for
  `ErrDenied`.
