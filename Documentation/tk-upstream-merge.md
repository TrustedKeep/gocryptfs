# Merging a new upstream gocryptfs release

This fork tracks [rfjakob/gocryptfs](https://github.com/rfjakob/gocryptfs) by
merging its release tags. This document is the procedure and, more importantly,
the fork-specific knowledge needed to resolve the conflicts correctly.

Anchor as of this writing: upstream `v2.6.1`, merged in `0f1575c`.

## Prerequisites

One-time, per clone:

```bash
git remote add upstream https://github.com/rfjakob/gocryptfs
git config rerere.enabled true    # replays your resolutions if the merge is redone
```

`rerere` matters more than it looks. These merges usually get attempted,
abandoned, and restarted at least once; without it you resolve the same conflicts
twice.

Go access to the private `github.com/TrustedKeep` modules in `go.mod` (`tkutils`,
`boundary`) is assumed, i.e. `GOPRIVATE=github.com/TrustedKeep/*` and working git
credentials.

## Procedure

Every step is run by a human. Nothing is gated by automation, by design: each
conflict needs judgement, and a green check would mostly be measuring the wrong
thing given the state of `tests/`. There is exactly one script,
`check-deletions.bash`, and it exists because it checks something you cannot see
by reading merge output.

### 1. Resolve the upstream release tag

```bash
git fetch --tags upstream
SYNC_VERSION=$(git tag --list --merged upstream/master --sort=version:refname \
  | grep -E '^v[0-9]+\.[0-9]+(\.[0-9]+)?$' | tail -1)
echo "$SYNC_VERSION"
```

Both filters are load-bearing.

**`--merged upstream/master` and the `vX.Y[.Z]` pattern.** Without them the
newest tag is one of *ours*, because version ordering places `v2.6.1-tk.1.0`
*after* `v2.6.1`:

```
v2.6.1
v2.6.1-tk.1.0      <- newest, if you do not filter
```

So `git tag --sort=version:refname | tail -1` resolves to our own tag, `git merge`
reports a successful no-op, the sync silently does nothing, and the follow-up tag
becomes `v2.6.1-tk.1.0-tk.1.0`. The pattern excludes every suffixed tag -- ours and
upstream pre-releases such as `v2.0-beta3` alike -- so only real upstream releases
reach `tail -1`.

**`--sort=version:refname`** is git's own version ordering, so this needs nothing
but git. Do not substitute `sort -V`: that is a GNU coreutils extension and this
fork also builds on darwin. The two agree on every tag shape in use here, `-tk`
suffixes and multi-digit components included.

### 2. Merge, without committing

```bash
git checkout -b tk-<ticket>-merge-"$SYNC_VERSION"
git merge --no-ff --no-commit "$SYNC_VERSION"
```

### 3. Re-delete the removals that conflicted

This fork deletes whole upstream subsystems, so a merge produces a pile of
delete/modify conflicts. List them **and read the list** before deleting anything:

```bash
git status --porcelain | grep -E '^(DD|AU|UD|UA|DU|AA|UU) '
```

Only two of the seven unmerged states are safe to resolve by deleting:

| State | Meaning | Action |
|---|---|---|
| `DU` | deleted by us, modified by them | `git rm` -- the intended-removal case, and the bulk of them. **Unless the path was renamed rather than removed** -- see below. |
| `DD` | deleted by both | `git rm` -- resolves it |
| `UD` | **deleted by them, modified by us** | **stop.** Contains our changes. Keep ours (`git add`) or accept the deletion (`git rm`), per file. |
| `AA` | added by both | **stop.** Two candidate versions; reconcile them. |
| `AU` | added by us | **stop.** Our new file. |
| `UA` | added by them | **stop.** Usually `.merge-deletions` business, see step 4. |
| `UU` | modified by both | **stop.** Ordinary textual conflict, see "Resolving conflicts". |

To generate just the safe-to-delete list:

```bash
git status --porcelain | awk '$1=="DU" || $1=="DD" {print $2}'
```

Read that output, then `git rm -rf -- <paths>`. Do not pipe it straight into
`git rm`: widening the filter to the other states silently discards TK changes
(`UD`) and both candidate versions (`AA`), and `$2` breaks on paths containing
spaces. There are none today, which is exactly how that mistake survives review.

**One `DU` case is not a removal: a rename.** This fork renamed six upstream test
files to add a platform suffix, so upstream still carries the old name:

```
tests/cli/cli_test.go                        -> cli_test_linux.go             (84%)  [1]
tests/defaults/main_test.go                  -> main_test_linux.go            (100%) [1]
tests/matrix/concurrency_test.go             -> concurrency_test_linux.go     (100%) [1]
tests/sharedstorage/sharedstorage_test.go    -> sharedstorage_test_linux.go   (100%) [1]
tests/plaintextnames/plaintextnames_test.go  -> plaintextnames_linux_test.go   (97%)
tests/root_test/root_test.go                 -> root_linux_test.go            (99%)
```

`[1]` These four put the suffix in the wrong position: Go strips `_test` *after*
checking the platform suffix, so `foo_test_linux.go` is a regular source file, not
a test file, and its tests never run. See "What is not verified". Do not "fix"
them by reverting the rename -- the correct form is `foo_linux_test.go`.

Similarity is 84-100%, well above git's 50% default, so rename detection normally
notices and applies upstream's change to the renamed file -- you get a `UU` in the
new name rather than a `DU` in the old one. But if someone rewrites one of these
enough to drop below the threshold, upstream's next change to it arrives as a `DU`
on the old path, and `git rm` throws that change away silently. If a `DU` path is
one we *renamed* rather than deleted, port the change into the new name instead.
The manifest deliberately does not list these paths for the same reason: the
content still exists, so the guard must not fire on them.

### 4. Check for invisible re-additions

```bash
./check-deletions.bash
```

`git status` only flags files we deleted that upstream also *modified*. When
upstream **adds** a file underneath a path we removed there is no conflict at all:
our side deleted the parent, their side created something new, and the merge takes
theirs silently. **Run the guard even when the merge reports zero conflicts** --
zero conflicts is exactly when this bites.

This is not hypothetical. The v2.6.1 merge absorbed
`tests/reverse/force_owner_test.go` and `.github/dependabot.yml` this way and
nobody noticed. Both paths are listed now, so that class is guarded.

A dry run of `upstream/master` shows the next batch already queued: four new files
under `internal/fusefrontend_reverse` and `tests/reverse/config_custom_test.go`.
All five are covered, so the guard will stop them.

### 5. Resolve, verify, complete

Resolve the remaining conflicts (see "Resolving conflicts"), run the checks in
"Verification", then:

```bash
git merge --continue
git tag "$SYNC_VERSION"-tk.1.0
git push origin "$SYNC_VERSION"-tk.1.0
```

## Resolving conflicts

50 upstream files carry TK modifications, but conflicts concentrate in six. For
each, this is the TK logic that must survive.

| File | What must survive |
|---|---|
| `internal/contentenc/content.go` | `(envelopeID string, wrappedKey []byte)` on **8** signatures, appended to the AD by `concatAD`. Also: a nil `fileID` is zero-padded to 16 bytes, where upstream omits it. Upstream churn here is usually block-batching performance work -- reapply it, then re-thread the TK parameters through every new or changed call site. |
| `internal/cryptocore/cryptocore.go` | `New(aeadType, IVBitLen, keyPool, useHKDF, rootID, wrappedKey)`. Keys come from `tkc`, never from a config masterkey. `keyPool == -1` selects envelope mode. Only `BackendGoGCM` and `BackendXChaCha20Poly1305` exist; OpenSSL and AES-SIV backends are gone. |
| `internal/fusefrontend/file.go` | Envelope attributes cached on the open-file-table entry (`EnvKeyID`, `Wrapper`), populated by `initializeEnvelopeKey()` after `createHeader()` and by `getEnvelopeAttrs()` (xattrs) when reading an existing file. |
| `mount.go` | `tkc.Connect(...)` before `initFuseFrontend`; the `CEK` flag-file flow that creates or loads the root envelope key; `keyPool` read from the config. |
| `cli_args.go` | Absent flags stay absent: `-masterkey`, `-fido2*`, `-exclude*`, `-reverse`. Upstream keeps adding flags to this file; take theirs, then re-remove ours. |
| `internal/configfile/config_file.go` | TK fields (`KeyPool`, `EnvelopeID`, `EnvEncAlg`, `BoundaryHost`, `NodeID`, `Mock*`, `IsSearch`); no `ScryptObject`, no `EncryptedKey`. |

### The recurring semantic risk

Textual conflicts are the easy part. The dangerous case is upstream adding a
**new code path** that our patches never saw. Two rules:

1. **Any new site that writes a file header needs the envelope hook.** Grep the
   merged tree for `createHeader()` and confirm each call is followed by
   `initializeEnvelopeKey()` when `args.Envelope` is set. Currently two sites:
   `file.go` (`doWrite`) and `file_allocate_truncate.go` (`truncateGrowFile`).
2. **Any new AEAD call site needs the TK parameters.** Grep for
   `EncryptBlock`, `DecryptBlock`, `EncryptBlocks`, `DecryptBlocks` and confirm
   every caller passes an envelope ID and wrapped key (or `""`/`nil` deliberately,
   as `root_node.go` does for symlinks and xattrs).

Upstream has already moved TK-patched code once: in the v2.6.1 merge, `Readdir`
relocated from `node_dir_ops.go` into the new `file_dir_ops.go`, and the filter
hiding `CEK` from directory listings had to move with it. Expect that again.

### Things that look safe to change but are not

- **Exit codes in `internal/exitcodes/exitcodes.go` are an external contract.**
  Removed codes are kept as `// skip 14`, `// skip 29` placeholders on purpose.
  Never renumber to close a gap.
- **The module path stays `github.com/rfjakob/gocryptfs/v2`.** Renaming it would
  touch every import in the tree and multiply the conflict surface for no gain.

## Verification

Run these before `git merge --continue`, in this order:

```bash
./check-deletions.bash

# go.mod and go.sum are touched by both sides of every merge, so a stale require
# line is a routine outcome. If this changes anything, keep the change.
go mod tidy && git diff --stat -- go.mod go.sum

./build.bash
go vet ./...
go test -count 1 ./internal/... ./ctlsock/...
```

| Check | Why it is here |
|---|---|
| `check-deletions.bash` | the invisible re-additions from step 4 |
| `go mod tidy` | both sides touch `go.mod`/`go.sum` every merge; a leftover `require` line is routine |
| `build.bash` | the real gate. TK signatures differ from upstream's, so a dropped envelope parameter fails to compile. |
| `go vet ./...` | the class of mistake the compiler misses |
| `go test ./internal/...` | unit tests, including the content-encryption round-trips |

`build.bash` is the one that catches most merge damage, because the TK divergence
is largely in function signatures. Run it before the tests -- some unit tests spawn
the binary it produces.

### Known-red at the v2.6.1 anchor

**`go vet` and `unit tests` fail on this anchor, and that is expected.** Do not
read it as merge damage.

`go vet`'s non-constant-format-string check is gated on the `go` directive in
`go.mod`. The v2.6.1 merge raised it from `go 1.22.9` to `go 1.24.0`, which
switches the check on for three upstream-owned lines this fork never touched:

```
internal/tlog/log.go:76         non-constant format string in (*log.Logger).Printf
internal/syscallcompat/quirks.go:21   ... in tlog.toggledLogger.Printf
mount.go:463                    ... in tlog.toggledLogger.Printf
```

`go test` fails for the same reason -- it runs its own vet subset including this
check. `go test -vet=off` skips it if you need the tests to run in the meantime.

v2.6.1 was tagged 2025-08-10 and predates upstream noticing. Upstream fixed those
exact lines in `4762992` (2025-12-14), which is **post-v2.6.1 and unreleased**, so
the fix arrives on its own with the next release tag and both failures clear
themselves. Nothing here suppresses them, so any *new* vet finding is equally
visible -- know these three by sight and treat a fourth as a real finding.

If you do choose to fix them before then, **copy upstream's text verbatim** --
`Print` and `Println` instead of `Printf`, exactly as in `4762992`. Matching
byte-for-byte means the next merge sees the same change on both sides and resolves
silently; an equivalent-but-different fix such as `Printf("%s", ...)` manufactures
a conflict for no benefit. Even done correctly, `quirks.go` still conflicts once,
because `ed5f848` later renames `logQuirk` to `LogQuirk` -- take theirs there. And
be aware you are then carrying forward-ported upstream content on a branch
documented as anchored at v2.6.1, which is why it was left alone here.

There is deliberately **no CI**. Verification is manual so that a human, with
agents, inspects each merge, and because an automated green check would mostly be
measuring the wrong thing while `tests/` is dead. Upstream's
`.github/workflows/ci.yml` stays in `.merge-deletions`; it exercises reverse mode,
openssl and scrypt, none of which exist here.

The commands above do not cover everything. Still on you once they pass:

- smoke-test a real mount against the KMS: `-init`, mount, write, unmount,
  remount, read the same data back
- confirm an existing filesystem created by the *previous* TK build still mounts
  and reads, i.e. the merge did not change the on-disk format

### What is not verified

The integration suite under `tests/` has been non-functional since TK key
management replaced password and masterkey auth: every `TestMain` mounts with
`-zerokey`, which is still parsed but no longer wired to anything. Four test
files are also misnamed `*_test_linux.go`, which Go treats as regular source
files rather than tests. Tracked as a follow-on; do not read a red `./test.bash`
as merge damage.

## Tagging

TK builds are tagged `<upstream release tag>-tk.<major>.<minor>`:

```
v2.6.1-tk.1.0    first TK build anchored on upstream v2.6.1
v2.6.1-tk.1.1    same anchor, additive TK change
v2.6.1-tk.2.0    same anchor, TK change that gates behaviour
v2.7.0-tk.1.0    first TK build after the v2.7.0 merge
```

Three independent numbers, read left to right: **which upstream we are anchored
to**, **which TK contract**, **which TK build of that contract**.

`major` is the part features gate on. Bump it when TK behaviour changes in a way
a consumer must opt into or branch on -- a new key-provider mode, an on-disk or
wire-format change, a flag whose meaning changes. Bump `minor` for everything
else: additive changes, fixes, and rebuilds that any consumer of the same major
can take blindly. That makes `tk.major` the thing to test in a feature gate, and
`>= tk.1.2`-style comparisons meaningful within a major.

The upstream anchor resets the TK numbers: the first build after a new upstream
merge is `-tk.1.0` again. The anchor already distinguishes it, and carrying TK
majors across upstream merges would conflate "TK contract changed" with "upstream
changed", which is exactly what the three-part scheme exists to separate.

### Why the upstream tag as the prefix

**It states the anchor.** This fork carries roughly 45 modified upstream files and
70 deletions, so "which upstream release is this built on" is the first question in
any bug report or CVE triage. The tag answers it without a git archaeology session.

**It makes `git describe` self-describing.** `build.bash` bakes
`git describe --tags --dirty` into the binary, so a build reports `v2.6.1-tk.1.0`
on the tag and `v2.6.1-tk.1.0-7-gabc1234` seven commits past it -- anchor, TK
contract, TK build and distance in one string.

**It keeps tag selection mechanical.** The `^v[0-9]+\.[0-9]+(\.[0-9]+)?$` pattern
in step 1 rejects anything carrying a suffix, so our own tags cannot be mistaken
for an upstream release no matter how many of them accumulate.

### Why two TK numbers rather than one

Tags are immutable references. TK work lands continuously against a fixed upstream
anchor -- cleanups, refactors, feature work -- so there will be several TK builds
per upstream release. A bare `-tk` would mean force-pushing a tag other people
have already fetched every time.

One counter would solve that, but it makes every TK build look equally
significant, so anything gating on it has to gate on an exact build. Splitting
into `major.minor` lets a consumer say "needs `tk.2`" and keep working across
`tk.2.1`, `tk.2.2` and so on, while a genuine contract change is visible in the
number it has to check.

Ordering behaves, including multi-digit components and the major rollover that
trips naive sorts. `git tag --sort=version:refname` yields:

```
v2.6.1
v2.6.1-tk.1.0
v2.6.1-tk.1.2
v2.6.1-tk.1.10
v2.6.1-tk.2.0
v2.6.1-tk.10.0
v2.7.0
```

That is git's ordering, not the shell's, so it holds wherever git does. Nothing
else parses these for you, though: anything gating on the TK version must split
the tag on `-tk.` and compare the two components **numerically**. Compare the
strings lexically and `tk.1.10` sorts before `tk.1.2`.

### Keep other tag namespaces out of this repo

`git describe` picks the nearest reachable tag regardless of naming scheme, so a
tag from an unrelated scheme silently becomes the version string baked into every
binary built after it. If another product needs its own tags, it needs its own
repo.

### These tags are always pinned, never resolved

TK builds are consumed by pinning an exact tag. Nothing resolves a version range
against them, so the scheme does not have to satisfy any resolver's ordering
rules -- only git's version ordering and a human reading a version string, both of which it
does satisfy. Keep it that way: if something ever wants to *resolve* a range here
rather than pin, revisit the scheme before adding the dependency.

## Maintaining `.merge-deletions`

The manifest lists paths that exist upstream but are intentionally absent here.
Add an entry whenever you delete an upstream subsystem, with a one-line reason.

**The guard only checks what the manifest lists, so an unlisted path is unguarded
by construction.** If you delete something during a merge and do not add an entry,
the next merge quietly brings it back. That is the whole failure mode this file
exists for, so treat adding the entry as part of the deletion, not a follow-up.

When the guard fires, decide per path:

- still unwanted: `git rm -rf <path>`
- now wanted: delete its line from the manifest, and say why in the commit message

One entry is commented out pending cleanup: `internal/readpassword`, which has had
zero importers since the masterkey removal. Uncomment it as the removal lands.

The manifest can rot in the other direction too: if upstream deletes something
we also deleted, our entry becomes dead weight rather than a false alarm.
Harmless, but worth a pass every few releases.
