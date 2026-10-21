# Phase 3.5 — Multi-mount `-sharedstorage` (TK-1720)

Phase 3 made the key ring mutable (rotation, op counts, rekey) and, to stay correct, allowed one mount
per filesystem. This phase lets several TKFS processes mount one cipherdir at once — on one host, or on
several hosts over NFSv4.1+/EFS — with the capability TKFS v1 and upstream v2.6.1 `-sharedstorage` had:
every mount sees the others' changes; concurrent writes to *different* files are safe; concurrent writes
to the *same* file are not guaranteed.

Branch `feature/tkfs-v2-phase3.5-sharedstorage` off `feature/tkfs-v2`@`b80a94f`, with Phases 4 and 5
merged. This document covers TK-1720: Parts 1 and 2 in gocryptfs, and Part 3, per-mount registry
records across tkutils, keep and gatehouse (§10). Instance binding is out of scope: a gateway that requires it refuses `-sharedstorage`
on every call (TK-1394), and the mount exits 35.

---

## 0. Settled decisions

**0.1 — Key state is write-once again.** v1 multi-mount worked because no key file changed after the
first mount. v2 keeps that property by construction: a ring entry is a file created once and never
rewritten or removed, and the only shared file a mount ever rewrites is its own op-count shard.

**0.2 — No lock guards key material.** A ring index is claimed with `link(2)`, which the backing
filesystem arbitrates. Locks on NFS can be silently local, lost with a lease, or held by a hung peer;
none of that can lose a key here. The one lock that remains (§6) is a same-host guard against mixing
shared and exclusive mounts.

**0.3 — One active key per filesystem.** The write key is the ring's head. A mount that loses a race
adopts the winner's entry instead of appending its own, so a rotation, however many mounts trigger it,
adds one entry.

**0.4 — Mounts learn each other's keys.** Every object still carries an explicit index (Phase 3 §0.1).
An index a mount does not hold triggers one bounded attempt to learn it; there is still no trial
decryption.

**0.5 — The ring lives in the cipherdir, whatever `-config` says.** Every mount of a cipherdir must
share one ring; a ring beside a per-host config would split it. Consequence: `-config` no longer keeps
the wrapped ciphertexts off the cipherdir's storage. They remain useless without the key service.

**0.6 — The Phase-3 ring format is refused, not migrated.** Phase 3 is unreleased. A cipherdir with a
regular file `KR` fails to mount with a message to re-init and copy the data.

## 1. On-disk layout

All under the cipherdir root. `KR` stays the one reserved name, so the root filters do not grow.

| Path | Content | Writers |
|---|---|---|
| `KR/` | directory, 0700 | created by the first writable mount |
| `KR/NNNNN` | ring entry for index NNNNN (5 decimal digits): JSON `{KeyID, Ciphertext, CreatedAt}`, 0400 | published once by `link(2)`; never rewritten or removed |
| `KR/ops/NNNNN.<mountID>` | `{Count}`: this mount's total encrypt operations under index NNNNN | only its owner, by tmp + rename |
| `KR/format` | the config's format-defining fields (§6) | published once by `link(2)` |
| `KR/xattr.lock` | empty; byte-range lock target (§7) | none |
| `KR/nodes/<SHA-256 of NodeID>` | empty; one mount's NodeID lock (§10) | created by its first holder; never removed |
| `KR/.tmp.<mountID>.<seq>` | staging for every publish | its owner; garbage-collected after 1 h |

`mountID` is 16 random bytes in hex, one per process. `OpCount` leaves the entry, and `KR.tmp` is retired.

## 2. Publishing

`publish(dst, bytes)`:

1. Write and fsync `KR/.tmp.<mountID>.<seq>` (`O_CREAT|O_EXCL`).
2. `link(tmp, dst)`. Success: won. `EEXIST` or any other error: read `dst`. Byte-equal to ours: won (an
   NFS reply lost after the LINK landed). Different: lost. Absent: retry, at most three times.
3. Unlink the tmp, then fsync `KR/` (fatal). Adopting a peer's entry also waits for this fsync, so an
   adopted entry is durable before anything is written under it.

Byte-equality proves authorship because every `Ciphertext` is a fresh wrap. The root `gocryptfs.diriv`
(§4) and `KR/format` (§6) are published the same way.

## 3. Learning and the write key

A mount's in-memory key sets cover a prefix of the ring. **Refresh** re-reads `KR/` and, for each entry
past that prefix, in index order: checks `KeyID` against the instance identity, unwraps it, and installs
its content and name keys at that explicit index. The write key then moves to the highest index installed.
An entry that fails to unwrap stops the refresh there; the next one retries.

Refresh runs every 10 s, before every heartbeat and op-count flush, at the start of every rotation, and
on a **miss**: content, symlink, xattr or name decryption meeting an index past the prefix. A miss makes
one unwrap attempt and backs off per index (1 s doubling to 60 s), so a bogus index costs little. Network
calls never run inside a FUSE operation except this bounded one.

`doWrite` resolves the header's index before encrypting, so writing into a sibling's newer file learns its
key and a file under a hole returns EIO. That also removes a live Phase-3 panic: `doEncryptBlock` used to
`log.Panicf` on an index the mount did not hold.

A missing entry below the highest (deleted from disk) is a hole, as in Phase 3 §0.8: fatal for the head
and, with encrypted names, for index 0. If the on-disk head stays unlearnable for a heartbeat interval,
a writable mount ends (`RotateFailed`): it would otherwise keep drawing nonces under a key nothing rotates
away from. An auto or rekey rotation that meets such a head returns without rotating and leaves it to this. A refresh refused by the key service ends the mount, from the monitor goroutine rather than a FUSE
thread: as a revocation (`ErrDenied`), or with exit 35 when the gateway requires binding.

## 4. First mount

1. `mkdir KR` (EEXIST is fine), fsync the cipherdir. Load the ring.
2. Empty ring: the cipherdir must hold nothing but the config, `KR` and the root diriv. If it holds more, reload — a peer that won publishes entry 0 before it
   serves, so payload with no entry 0 is still the Phase-3 refusal.
3. Mint (empty identity). The connector no longer adopts the identity a mint returns; the caller adopts
   it after winning.
4. Publish the root `gocryptfs.diriv` (§2) unless `-plaintextnames`. EEXIST with a valid diriv
   (18 bytes, index 0, the deterministic-names IV rule) is accepted; the diriv does not depend on the key,
   so any mix of winners is consistent. A malformed leftover from a crashed Phase-3 first mount is
   removed and republished.
5. Publish `KR/00000`. Won: use the fresh key. Lost: discard it, reload, unwrap the winner's entry 0. The
   loser's KEK is orphaned in keep, as a retried mint's already is (Phase 3 §12.7).
6. `AdoptIdentity(ring.KekID())`.

## 5. Rotation and op counts

**Rotation** (ctlsock, rekey and auto share one path; one at a time per process):

1. Refresh. Re-check the trigger: an auto rotation whose head moved since the flush that called it, or a
   rekey whose head is already past the index the heartbeat reported, returns the head without generating.
2. Generate, outside any ring lock.
3. Refresh again and publish at the known length L. Won: install L and make it the write key. Lost:
   discard the key, refresh (which learns the peer's L), adopt it. A ctlsock rotation that finds the head
   moved still publishes on top.

**Rekey** loops at most three times: rotate (or adopt), re-heartbeat, and stop as soon as keep no longer
commands a rekey. keep judges a directive per heartbeat (`OutstandingFor`), so mounts that adopt the head
satisfy it together and one directive adds one entry, with no server change.

**Op counts.** contentenc hands out a fresh counter whenever the write key changes; the rotator keeps
every counter it was given, per index. A mount's total under an index is its base plus the
sum of those counters, so it only ever grows — draws that land on a counter after it was replaced are
still counted at the next flush. A flush (every heartbeat interval, and once at unmount):

1. Refresh, then write this mount's shard for every index at or above the head whose total changed.
2. Sum the head's shards. A peer shard whose mtime is three heartbeat intervals older than ours belongs to a
   dead mount: add it to our base, rewrite ours, then unlink theirs (a crash in between overcounts, the
   safe direction).
3. Unlink shards for indices below the head (their budget no longer matters) and staging older than 1 h.
4. Rotate when the sum reaches the threshold. A missing shard is skipped; an unparsable one counts as due,
   so one rotation retires it.

The nonce argument of Phase 3 §12.2 carries over per key: the threshold now bounds the draws of every
mount under that key together.

**Teardown.** The final flush runs once, at unmount or before a shutdown the monitor itself started.
After it the rotator refuses to learn, rotate or flush, so nothing writes the cipherdir.

## 6. Guards

- **Mode lock.** A flock on the cipherdir's own fd, held for the mount's life: `LOCK_SH` with
  `-sharedstorage`, `LOCK_EX` without. A non-shared mount still refuses, and is refused by, any other
  mount on the host (exit 32); shared mounts coexist. Across hosts it is advisory or local, and nothing
  depends on it.
- **Storage gate.** `-sharedstorage` refuses a backing filesystem it cannot vouch for, from
  `/proc/self/mountinfo` (so it is Linux-only): local filesystems pass; `nfs4` passes at `vers≥4.1`,
  mounted `hard`, with no `nolock` or `nocto` and `local_lock=none`; NFSv3, CIFS, `fuse.*` and anything
  unrecognized are refused. A filesystem without hard links falls back to rename for a non-shared mount,
  which its exclusive lock makes the only writer.
- **Format fingerprint.** `-config` can differ per host, so `KR/format` records `Version`,
  `FeatureFlags` and `LongNameMax` at the first mount. A mount whose config disagrees is refused.
- **NodeID lock.** Two live writable `-sharedstorage` mounts cannot share a NodeID (§10); the second exits 32.

## 7. Xattr markers (Part 2)

The first encrypted xattr on an inode stamps `user.gocryptfs_keyidx.<n>` (Phase 3 §3.5). Two mounts
stamping under different write keys would leave two markers, and every xattr operation on that inode would
then fail. Under `-sharedstorage` the stamp takes an OFD write lock on `KR/xattr.lock` at a byte derived
from the inode number, and re-reads the markers under it. This one does depend on locks spanning hosts;
EFS has no xattrs, so it matters only on other NFSv4.2 servers.

## 8. Not covered

- Same-file concurrent writes (upstream master's unreleased byte-range locks arrive with the next upstream
  merge); application locks are not forwarded between mounts.
- A hard per-mount block: NodeID is self-asserted (§10). `-fsck`.

## 9. Tests

- **configfile:** concurrent publishers on one index (one winner, every loser told so); EEXIST after a
  landed link resolves to won; gaps load as holes; a regular-file `KR` is refused; shard sum, absorb and GC;
  staging GC.
- **contentenc / nametransform:** explicit-index installs; the miss hook fires only past the prefix; a
  trailing unlearned index never becomes the write key.
- **rotate:** two rotators on one cipherdir with separate key sets — concurrent rotations add one entry;
  a lagging mount adopts instead of panicking; a flush credits the index the draws were made under; a
  rekey seen by both adds one entry.
- **Integration:** two `-sharedstorage -mock-kms` mounts on one host — a rotation on one is read and
  written through the other; racing first mounts converge on one key and one root diriv;
  `tests/sharedstorage` restored from `257f492`; the test helpers wait for the process to exit, which ends
  the `tests/matrix` ENOTEMPTY flake.
- **Part 3:** a second mount with a live mount's NodeID exits 32, and the NodeID frees at unmount; keep
  keeps one record per NodeID across remounts and derives the instance view; a rekey's `PastIdx` comes from
  live mounts; Forget removes every mount; gatehouse forwards `MountID` and proxies the mount delete.
- **Manual acceptance:** two hosts on EFS against a real gatehouse + keep.

## 10. Per-mount registry (Part 3)

Every mount of a filesystem used to heartbeat into one `tkfsi/<kekID>` record in keep, so the mounts
overwrote each other's key index, host and last-seen time.

**NodeID names a mount.** It is minted at `-init` into the config, and keep only requires it, matches the
blocklist on it and records it: unwrap is scoped by tenant and KekID, the ACL by DN. `-node-id` at mount
overrides the config's, so one mount needs nothing and each further concurrent one passes its own, or has
its own `-config`. The heartbeat also carries the random per-process `MountID`.

**Dedup.** A writable `-sharedstorage` mount holds a flock on `KR/nodes/<SHA-256 of NodeID>` for its life, and a
second mount with the same NodeID exits 32. On NFS the flock is a whole-file lock held by the server (the
storage gate requires `local_lock=none`), freed when a crashed holder's lease runs out. Lock files are never
removed, since unlinking one that a peer may be locking races. A lapsed lock costs little: op-count shards
stay keyed by the mount ID, so two processes sharing a NodeID only make its record flip, which keep logs.

**keep** stores one `TKFSMount` per mount at `tkfsm/<kekID>/<hex NodeID>`, replacing `tkfsi`:

- A heartbeat upserts its record; keep keeps `FirstSeen` and sets `LastSeen` and `Route`. The record also
  remembers the process before its latest, and a live record switching back to it is logged as a shared
  NodeID: a remount brings a new random `MountID`, and only a second process brings an old one back.
- The instance view, `TKFSInstance{KekID, Mounts, Rekey}`, is a prefix scan. A record stays until an admin
  deletes it; one silent for `TKFSMountLiveFor` (15 min) shows as unreachable.
- A rekey's `PastIdx` is the lowest index a live mount reports, or any mount's when none is live. Mounts
  assert their own index, so the lowest is the one no mount can push up to hold a rekey open; the key's
  creation time is what a mount must move past. keep commands it on every heartbeat that reports an older
  key, as before, and it is done once no live mount is `OutstandingFor` it.
- An undecodable rekey directive is logged and skipped, so a new rekey or a Forget replaces it.
- Forget deletes the instance's mounts along with its rekey and binding.

| keep route | gatehouse admin route (`/api/v1/tkfsdatakey`) | |
|---|---|---|
| `PUT /tkfsinstance` | (the gateway's heartbeat) | body `TKFSMount` |
| `GET /tkfsinstance[/:kekID]` | `GET /instances`, `GET /instance/:kekID` | `[]TKFSInstance`, `TKFSInstance` |
| `DELETE /tkfsinstance/:kekID/mount?nodeID=` | `DELETE /instance/:kekID/mount?nodeID=` | one mount record |
| `DELETE /tkfsinstance/:kekID` | `DELETE /instance/:kekID` | Forget |

**Admin UI.** The instances table has a row per mount, and binding-only instances keep theirs. A mount
row can be deleted, "Clear unreachable" deletes every mount silent for 15 minutes, blocked ones included,
and a live mount still outstanding for a rekey shows it pending. Block from a mount row starts from that
mount's NodeID and KEK ID. A NodeID block now stops one mount, and it is soft: a blocked mount can
restart under another `-node-id`. Hard stops stay DN, KekID and machine.

The mock KMS store stays keyed by the config's NodeID, so `-mock-kms` mounts of one filesystem need configs
with the same NodeID, and tell themselves apart with `-node-id`.
