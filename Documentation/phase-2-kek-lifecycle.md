# Phase 2 — KEK key lifecycle (TK-1392)

Status: built, four review rounds applied (§0), **uncommitted**. Supersedes the
envelope/per-file-wrapped-key model with the KEK "single data key + HKDF-derive" model across init,
startup, and the content/filename crypto core.
Builds on Phase 1 (gateway mTLS client) and Phase 1.5 (transit-wrap; the `WipeCache` half did not
survive — see §0 round 3 item 10).

Companion docs: `phase-1.5-transit-wrap-and-key-hygiene.md`. Plan of record:
`~/.claude/plans/branching-off-of-this-snuggly-meadow.md` §6 (Phase 2), §7 (config/crypto).

---

## 0. As-built reconciliation (2026-07-27, refreshed 2026-07-30, 2026-08-04)

The sections below are the original design. What actually shipped this pass, and the deltas that
resolve the §13 open questions:

- **Review rounds 1–4 (2026-08-03 / 2026-08-04) — read this first, it supersedes parts of §0
  below.** Four rounds of the user's review reshaped the as-built substantially. The common thread
  is *remove anything unconditional or vestigial*: a flag set on every config describes nothing, an
  option with one legal value is not an option, and a Phase-2 stub is not worth documenting when
  deleting it is cheaper. The counterweight, from round 4, is **stay close to upstream**: where a
  fork delta buys nothing, prefer upstream's shape even if it is imperfect (see item 6). Items are
  numbered in the order they were raised; later rounds revise earlier ones in place.
  1. **`-zerokey` DELETED** (flag + field + every `confFile == nil` branch). It meant "mount with no
     config file at all" and was test-only; the mock gateway covers the same ground honestly. This
     removed the whole nil-config code path, which had been the source of nil-deref bugs. A config
     is now mandatory at mount.
  2. **The key ring moved out of `gocryptfs.conf` into its own file, `KR`** — the repurposed old
     `CEK` file (`internal/configfile/keyring.go`). `-init` writes **no ring file at all**; the
     absent file *is* the freshly-initialized state, restoring the original `CEK` semantics. A
     zero-length ring is an **error**, not "fresh" — treating a truncated write as fresh would
     regenerate a key over existing data. The rationale for the split: the config stays a static,
     human-editable description of the filesystem that no mount ever rewrites, and the one file that
     does get rewritten (first mount, and rotation in Phase 3) holds nothing but ciphertext.
  3. **`FlagGatewayKEK` and `FlagHKDF` both removed entirely.** Unconditional means implied; the
     version check alone gates the format. HKDF derivation is likewise unconditional (see item 5),
     so there is no non-HKDF mode a flag could select.
  4. **Per-file header gained `KeyIdx uint16`** — `HeaderLen` 18 → 20, layout
     `[Version u16][KeyIdx u16][Id 16B]`, `RandomHeader(keyIdx)`. `keyIdx` is threaded through the
     whole `contentenc` encrypt/decrypt API and cached in `openfiletable.Entry`. Reserved now rather
     than in Phase 3 so rotation is additive instead of another format break. **`KeyIdx` is
     deliberately NOT in the AAD**: the AEAD tag already binds the key that was used, so
     authenticating the selector adds nothing (same treatment as `Version`).
  5. **HKDF derivation is mandatory** — the `useHKDF` parameter is gone from `cryptocore.New`. The
     asymmetry that prompted the question (XChaCha required it, AES-GCM did not) was purely
     historical: the non-HKDF path exists only to read v0.7–v1.2 filesystems, and XChaCha arrived in
     v2.2. It is also load-bearing, not ceremonial: EME uses its key as a raw AES-ECB key over
     **attacker-chosen** filenames while GCM uses its key for AES-CTR keystream, so with one shared
     key a filename block colliding with a `nonce‖counter` value would expose that keystream block
     as EME ciphertext on disk — which decrypts file content. Two derived keys remove the path.
  6. **`raw64` — removed in round 3, then restored in round 4 for upstream parity.** The flag, the
     `nametransform.New` parameter, and mount's `args.raw64 = confFile.IsFeatureFlagSet(FlagRaw64)`
     override are all back, byte-identical to upstream; `internal/nametransform/names.go` has no fork
     delta at all. **The flag is inert, deliberately**: `Create` sets `FlagRaw64` on every filesystem
     it writes and the config overrides the command line at mount, so no value of `-raw64` changes
     what lands on disk. That is why the matrix axis is *not* restored: a case for it would duplicate
     the "Normal" case while looking like coverage. Round 3's "EMENames requires Raw64" validate check
     is reverted too, since padded-name configs are legal upstream.

     **Inert *here*, not upstream** — worth understanding before touching this again. Upstream's
     `Create` also ignores the flag (see below), but upstream's `-raw64` is still reachable: the
     override is inside `if confFile != nil`, and upstream's own comment says confFile is nil "when
     `-zerokey` or `-masterkey` was used". On that config-less path the CLI value survives to
     `nametransform.New`, which is how upstream mounts a pre-v1.2 padded-names filesystem with
     `-masterkey` when there is no config to read the flag from. This fork removed `-masterkey`
     (long ago; see the `skip 14` note in `exitcodes.go`) and `-zerokey` (round 1 item 1), so
     `confFile` is never nil and the flag is unreachable. The inertness is a fork consequence.

     Sharper still: with `-masterkey` already gone, `-zerokey` was the *only* nil-config producer
     here, so before round 1 this flag was never a production knob either — it was a test-harness
     knob that worked only in combination with the test-only `-zerokey`, and `tests/matrix` passed
     the two together in one `opts` slice. It died with `-zerokey`; round 2 only noticed. Upstream
     diff parity is therefore the *whole* case for keeping it, which is why it is kept at the level
     of the `nametransform.New` signature — the line an upstream merge would actually conflict on.

     That parity is worth having because upstream's flag is load-bearing and will not go away:
     `tests/example_filesystems` passes `-raw64=false -hkdf=false` alongside `-masterkey` in **8**
     places, mounting each legacy (v0.4–v1.1) example filesystem a second time with no config, so
     the command line has to restate the on-disk format. That is the flag's real job. This fork
     deleted that whole tree (89 files) — consistently, since it has no password mode, no
     `-masterkey`, and format 3 refuses formats 1 and 2, making legacy filesystems unmountable by
     construction. Upstream keeping the flag means the signature is stable to merge against.

     **History, since "restore the gate" sounds easier than it is:** a working gate existed upstream
     only between 2016-11-01 (`2b991c9`, which introduced `-raw64`, gating on a positional
     `raw64 bool` argument to `CreateConfFile`) and 2017-03-05 (`decda6d` "configfile: switch on Raw64
     by default", which deleted the argument and the `if raw64` around the flag — Go 1.4 compat had
     been dropped and v1.3 was adding a feature flag anyway). `CreateArgs` came later still, so a
     `CreateArgs.Raw64` field has **never** existed. Making raw64 a real option again is therefore a
     new feature, not a restoration: gate `Create`'s `setFeatureFlag(FlagRaw64)` on a new
     `CreateArgs.Raw64`. Everything else is already wired — mount honours the config automatically.
  7. **Exit codes now match the cause.** `Validate` attaches its own code — version mismatch →
     `DeprecatedFS`, self-contradictory contents → `LoadConf` (via `badConf()`) — and `Load` stopped
     blanket-wrapping everything as `DeprecatedFS`, which had been telling operators to migrate
     filesystems that were merely corrupt. Read failure → `OpenConf`. Added `exitcodes.Err.Code()`.
  8. **Health check is fatal.** `-health-check-port` (default 8000) must bind or the mount exits
     with the new `exitcodes.HealthCheck = 31` — a mount nobody can probe is invisible to its
     supervisor, and a bind collision means one of the two mounts is misconfigured. The bind happens
     **before** the FUSE mount (next to the ctlsock early-open) so the fatal cannot leave a live
     mountpoint with no process behind it; serving starts before the ready signal so a supervisor
     probing on ready cannot race the listener. **A negative port disables** the endpoint — the
     opt-out for stacking mounts on one host, and what the test harness passes. **0 means unset**
     and resolves to the default: it is the int zero value, so `-health-check-port=0` and passing no
     flag are the same statement and must not mean different things (`resolveHealthCheckPort`).
     Round 4 corrected this — 0 initially meant "disable".
  9. **`Keyspace` DRY'd across repos** — the length-prefixed composition now has one definition,
     `model.TKFSKeyspace(dn, nodeID)` in tkutils. gatehouse's local `tkfsKeyspace` and the client's
     `tkc.Keyspace` (which nothing called) are gone. A drift between the two would have silently
     put a filesystem's KEK in a different keyspace than its unwraps were scoped to.
  10. **Dead code confirmed gone**: `tk_aead_{aes,cha,keys}.go` (per-block KMS key fetch keyed off
      the AAD envelope tail, plus two LRU caches), and `wipe.go`/`wipe_test.go` — `WipeCache` took an
      `lru.Cache` and no LRU cache survived the envelope rip, making it the last `tkutils/lru` user.
  11. **Format-2 tests and fixtures deleted** — `TestBrokenFsV14`, `TestMalleableBase64`, their
      fixtures, and the whole `tests/hkdf_sanity/` package. All four existed only to exercise
      format-2 filesystems, which this version refuses by design.
- **First-connection-on-mount redesign (2026-07-31).** `-init` no longer contacts the key service
  at all: it writes the config and (per round 2 above) **no key-ring file**. The
  first mount finds no ring, calls `GenerateTKFSDataKey`, persists the ciphertext-only
  entry via `WriteFile()` **before** using the key, and proceeds with `dk.Plaintext` (no redundant
  unwrap round-trip); later mounts unwrap the single active entry as before. This restores the
  pre-v2 shape where the first key-service connection happens at mount, not init. §4's
  "init generates" flow, §6's non-empty-ring gate, and §13-Q5's init failure semantics below are
  superseded accordingly. The generate branch (`generateInitialDataKey`) is guarded (adversarial
  review findings): competing first mounts serialize on an **flock over `gocryptfs.conf`** and
  re-load under the lock (loser unwraps the winner's entry instead of orphaning its own data with a
  second generate); `-ro` first mounts are **refused** (the pre-mount ring write is outside kernel ro
  enforcement — mount writable once, then `-ro`; this also means a never-mounted cipherdir on
  read-only media cannot be first-mounted); a missing ring over a cipherdir holding anything beyond
  config+diriv **fails closed** (`ensureCipherdirFresh` — a deleted ring must not
  trigger a silent rekey over existing data); `writeJSONAtomic` removes its tmp file on failure (a
  stale tmp would block every retry on the `O_EXCL` create) and fsyncs the directory after the rename
  so the persisted ring survives a crash that would otherwise revert it to absent and regenerate.
  The lock cannot be taken on the ring file itself — that is the file being created, and creating it
  early would expose a zero-length ring to a concurrent mount. It is on the config because that is
  the one file guaranteed to exist for the life of the filesystem; note that `flock` is advisory and
  conflicts only with another `flock()` on the same inode, so it blocks no ordinary I/O anywhere in
  the cipherdir, and it does **not** carry across hosts sharing storage (`-sharedstorage`).
- **gocryptfs client — DONE, unit + integration green.** Envelope ripped, unified KEK crypto,
  `DataKeyConnector` rename, KeyRing init/startup, version bump 2→3, `Validate` gating. Key hygiene
  as built: the master key is zeroized immediately after `cryptocore.New` (`initFuseFrontend`), and
  unmount drops the ciphers (`CryptoCore.Wipe()` still only nils the stdlib refs + forces a GC) and
  closes the data-key connector; making `Wipe()` zeroize derived key bytes is still deferred. New
  real-FUSE integration test `tests/tkfs_kek/` (8 tests) drives `-init`→mount→write→unmount→
  remount→read through the in-process mock gateway (`-mock-kms`) and asserts `-init` writes **no**
  ring file and the first mount a single ciphertext-only `KR` entry — plus that the ring file is
  hidden from a readdir of the mount, and that a first mount whose persist fails serves no I/O.
- **tkutils — DONE.** Added `model.ServiceTKFS` (EndpointServiceType) and a **shared** transit
  protocol in `model/transit.go` — `NewTransportKey(alg) (*rsa.PrivateKey, pubPEM, error)` (client
  side), `TransitWrap(alg, pubPEM, pt)` (server side), `TransitUnwrap(priv, wrapped)` (client side).
  Direct RSA-OAEP/SHA-256 with a nil label — no KEM-DEM/hybrid layer, no AES-GCM DEM, no framing:
  OAEP encrypts the 32-byte data key directly. Algorithms are gated by the unexported `transitAlgBits`
  allow-list (RSA-2048/3072/4096 only; anything else fails closed in both `NewTransportKey` and
  `TransitWrap`). The signatures use `*rsa.PrivateKey`/`*rsa.PublicKey`, **not** the `kem.Kem`
  interface — a KEM cannot encrypt a *chosen* plaintext (`kem.WrapFor` mints its own secret), so an
  interface would promise agility this protocol does not have. `kem.KemType` survives only as the
  wire discriminator carried in `TransportAlg`. Resolves open-Q3 (one shared helper, not duplicated).
- **keep — DONE.** New `web/tenantdatakey.go`: routes are **POST** (not PUT) `/keepsvc/tenantdatakey/
  {generate,unwrap}`, `gatewayOperation`-wrapped. **tenantID comes from the client cert**
  (`tenants.ProcessRequest` → `StreetAddress`), **not** the injectable `TenantID` header (closes
  finding #3 without depending on the separate `fix/processheaders-tenant-header-injection` branch).
  KEK `path` = request `NodeID`. Generate calls `TenantManager.KekWrap(tenantID, req.NodeID)`
  directly; unwrap calls the **new** `TenantManager.KekUnwrapScoped(tenantID, keyspace, kekID, ct)`,
  which stands in for the bypassed MCSE ownership check by requiring the requested `KeyID` to be the
  KEK the claimed keyspace *currently owns* (and failing closed when it owns none) — no MCSE either
  way. Also added `ServiceTKFS` to the `tcv/object_keywrap.go` MCSE bypass guard (both KekWrap +
  KekUnwrap) for the default gateway path, and routed `ServiceTKFS` unwrap there to `KekUnwrapScoped`
  as well, so both the gateway and search paths get the scoping.
  **What the scoping does and does not buy** (recorded in `KekUnwrapScoped`'s SCOPE note and covered
  by `TestKekUnwrapScopedDefeatedByFaithfulReplay`): the hard boundary is the cert-derived half of
  the keyspace — the tenant on the keep/search route, the DN on the gateway route. The `NodeID` half
  is self-asserted and lives in the same `gocryptfs.conf` as the `KeyID` and `Ciphertext`, so a
  caller holding a stolen config can replay the whole triple faithfully. This is **not**
  per-filesystem isolation.
- **gatehouse — DONE.** `management/tkfsdatakey.go` handlers un-stubbed: DN via
  `tcutils.CertificatesToClientDN(r.TLS)`, keyspace via the shared length-prefixed
  `model.TKFSKeyspace(dn, nodeID)` (see round 3 item 9) into `KekWrapRequest.Mount` /
  `KekUnwrapRequest.Mount`;
  `Service: ServiceTKFS`, `Creds: nil` (bypasses keep MCSE); tenantID = `config.Get().TenantID`
  (resolves open-Q2). It calls `oec.Get().KekWrap`/`KekUnwrap`, and keep routes the `ServiceTKFS`
  unwrap on to `KekUnwrapScoped` — so `Mount` is load-bearing on the unwrap path. Transit-wraps via
  `model.TransitWrap`, zeroizes plaintext.
- **Dev wiring — DONE.** keep + gatehouse pin the merged tkutils
  (`v2.16.1-0.20260730203651-829a3f44f5e6`, which carries `ServiceTKFS` + `model/transit.go`); the
  local `replace` directives are gone (gatehouse's is commented out). gocryptfs needs no re-pin —
  client/server interoperate over the JSON wire, not a shared compiled tkutils.
- **Test-harness `-mock-kms` injection — DONE.** `tests/test_helpers.InitFS` appends `-mock-kms` by
  default, backing off only when the caller already picked a key source (`-mock-kms` again, or
  `-search`); `needsMockKMS` is the guard. `Mount` likewise injects `-health-check-port=0`, because
  `go test ./tests/...` runs packages in parallel and they would otherwise fight over port 8000.
  The mock's bbolt path is no longer fixed — it is derived
  per-NodeID (`/tmp/tkfs_mock_gateway_<sanitized NodeID>.db`, `mockGatewayDBPath`), so parallel inits
  do not contend on one file lock. `tests/tkfs_kek.TestKEKLifecycleViaHarnessDefault` asserts the
  injection.
- **Still pending:** live cross-service E2E (default + search) against a running keep+gatehouse;
  search-mode integration test (needs the lizard ramdisk + keep:7070). `Validate()` reject-case unit
  tests **are now done** — `TestValidateExitCodes` (§10).
- **Gotcha for anyone re-verifying this work:** everything under `tests/` execs the prebuilt
  `../../gocryptfs`, which `go test` never rebuilds. Run `go build -o gocryptfs .` first and pass
  `-count=1`, or an integration suite will report `ok` for a binary that predates your change.

---

## 1. Goal & scope

Turn TKFS into a filesystem whose master key is a **single 32-byte AES-256 data key** issued by a
key service, KEK-wrapped at rest, unwrapped into memory at mount, and used stock-gocryptfs
style: HKDF-derive the EME (filename) key + the GCM/XChaCha content key from it; per-file random
128-bit IVs; **no** per-file wrapped keys, **no** inline-AAD envelope.

The wrapped key lives in a **`KR` file** beside `gocryptfs.conf` (§0 round 2 — the design originally
put it in the config, and the `CEK` file this repurposes originally held the envelope model's
key-encryption key). It holds only ciphertext; nothing plaintext is ever written.

Closes CR criteria **3** (encrypted key in config, no plaintext at rest) and **4** (decrypt on
startup, read/write works).

**This is a hard, intentional on-disk format break** (v1 envelope ↔ v2 KEK are incompatible;
fail-closed on old configs). Migration is the standard gocryptfs cross-version move — mount v1 with
the old binary and a fresh v2 with the new binary and `cp -a` across at the *plaintext* layer. No
auto-migration, no converter (Phase 5 runbook).

Cross-repo (all four move together this phase — per decision 2026-07-27):

| Repo | Work |
|------|------|
| **gocryptfs** | Rip envelope; unified KEK crypto core; KeyRing init/startup; connector unification + rename; search connector → KEK; unmount key hygiene. |
| **keep** | New tenant-token REST route `POST /keepsvc/tenantdatakey/{generate,unwrap}` backed by the existing `KekWrap` plus the new `KekUnwrapScoped` (for `-search`). |
| **gatehouse** | Un-stub the default-mode `tkfsdatakey/{generate,unwrap}` handlers (`oec.KekWrap`/`KekUnwrap` + transit-wrap). |
| **tkutils** | Reuse existing `model.TKFSDataKey*`; add a shared transit helper only if it removes duplication across keep+gatehouse+gocryptfs-test. (As built: it did — `model/transit.go`, see §0/§9.) |
| **lizard** | **None.** (Confirmed: exec seam + ramdisk provisioning unchanged; migration is ops-only.) |

---

## 2. Connector unification & rename

Both default (gateway) mode and `-search` mode now speak the same **generate / unwrap** protocol
against a KEK-holding service; they differ only in **endpoint + auth + cert source**. So the
interface name `GatewayConnector` is too narrow.

**Rename** `internal/tkc/gateway.go`:
- interface `GatewayConnector` → **`DataKeyConnector`** (methods unchanged: `GenerateTKFSDataKey() (TKFSDataKey, error)`, `UnwrapTKFSDataKey(keyID string, ciphertext []byte) ([]byte, error)`, `Close() error`).
- accessor `tkc.Gateway()` → **`tkc.DataKey()`**; package var `gw` → `dkc`.

Concrete implementations (all implement `DataKeyConnector`):

| Type | File | Target | Auth | Certs |
|------|------|--------|------|-------|
| `gwConnector` | `gwconnect.go` | gatehouse `:7083` `/api/v1/tkfsdatakey/*` | mTLS + per-op DN ACL | `-gateway-cert-dir` (`tls.crt`/`tls.key`/`ca.crt`) |
| `searchConnector` | `search_connect.go` (rewritten) | keep `:7070` `/keepsvc/tenantdatakey/*` | mTLS + tenant token | ramdisk (`gw.cert.pem`/`gw.key.pem`/`gw.ca.pem`/`gw.token`/`gw.hosts.json`) |
| `mockGatewayConnector` | `mock_gwconnect.go` | in-proc `tkutils/kek` + bbolt | none | none |

**Shared core — design vs as-built.** The design called for extracting *both* halves that
`gwConnector` and `searchConnector` have in common: the transit-wrap machinery **and** the
generate/unwrap request-build + POST + `TransitWrappedKey` unwrap, behind an unexported helper (e.g.
`type dataKeyTransport struct{ post func(path string, req, resp any) error }` with
`generate()`/`unwrap()` methods), leaving each connector to supply only its HTTP `post` (endpoint +
headers) and its cert loading.

**As built, only the transit helpers are shared:** `newTransport`/`unwrapTransit` live in
`gwconnect.go` and delegate to tkutils — `newTransport` calls `model.NewTransportKey(transportKemType)`
(which picks the RSA modulus size from the `transitAlgBits` allow-list; `kem.RSA3072` is just the wire
discriminator, not a keypair type), and `unwrapTransit` calls `model.TransitUnwrap` and then enforces
the 32-byte data-key length. The `dataKeyTransport` extraction was **not** done: each connector still
carries its own full `GenerateTKFSDataKey`/`UnwrapTKFSDataKey` (request build + POST + unwrap). Still
the open reuse win, and still what would keep the two real connectors honest about sending identical,
transit-wrapped payloads.

**`Connect()` selector** (`instance.go`), all branches now set `dkc` (the `KMSConnector` global
`c` and `Get()` are removed — see §3):

```
switch {
case isSearch:  dkc = newSearchConnector(id)                            // real, keep :7070
case mockKMS:   dkc = newMockGatewayConnector(id, "")                   // mock, bbolt at /tmp/tkfs_mock_gateway_<NodeID>.db
default:        dkc = newGatewayConnector(gatewayHost, certDir, id, mockAWS)  // real, gatehouse :7083
}
```

`-mock-kms` now selects the **mock gateway** (it used to select the envelope bbolt mock). This keeps
`-init` and the test suite runnable with no live key service.

---

## 3. gocryptfs — rip the envelope model

Delete / simplify (envelope-specific, verified against worktree tip `8ecb2c2`):

- **`internal/cryptocore/`**: delete `tk_aead_keys.go` (the two package LRU caches `keys` +
  `decryptedCache`, `getKey`/`getKeyName`/`parseAD`/`RetrieveKey`), `tk_aead_aes.go`, `tk_aead_cha.go`
  (per-block key-fetch AEAD shims). Replace with a single `cipher.AEAD` built once from the
  HKDF-derived content key (stock gocryptfs).
- **`internal/cryptocore/cryptocore.go`**: `New` signature changes from
  `New(aeadType, IVBitLen, keyPool int, useHKDF bool, rootID string, wrappedKey []byte)` to
  **`New(key []byte, aeadType AEADTypeEnum, IVBitLen int)`** (stock shape, minus `useHKDF` — §0
  round 3 item 5 made derivation unconditional). It takes the
  plaintext master key, HKDF-derives the EME key (existing `hkdfDerive(key, hkdfInfoEMENames, KeyLen)`)
  and the content key (`hkdfInfoGCMContent`/XChaCha info), builds one AEAD, zeroizes the derived key
  copies. Drop the `keyPool == -1` envelope branch and both `tkc.Get()` calls.
- **`internal/contentenc/content.go`**: drop the `envelopeID string, wrappedKey []byte` params from
  `DecryptBlocks`/`DecryptBlock`/`EncryptBlocks`/`EncryptBlock`/`doEncrypt*`/`encryptBlocksParallel`;
  `concatAD` returns to `[blockNo(8) | fileID(16)]` only. Those same functions then **gain a
  `keyIdx uint16`** (§0 round 3 item 4) — the envelope's per-file key id, reduced to a ring index and
  moved from the AAD tail into the file header. Selection happens in `ContentEnc.aeadForKey(keyIdx)`,
  which errors on any index but 0 today; writes use the `contentenc.WriteKeyIdx` const.
- **`internal/fusefrontend/file.go`**: delete `initializeEnvelopeKey` + `getEnvelopeAttrs`; remove the
  `user.envID`/`user.wrapped` xattr writes/reads and every `f.rootNode.args.Envelope` branch; content
  calls stop threading env id/wrapper.
- **`internal/fusefrontend/root_node.go`**: drop `rootEnvKeyID`/`rootWrappedKey` fields + the
  `NewRootNode` params; symlink/xattr encryption returns to stock (uses the content AEAD directly,
  no env surrogate).
- **`internal/fusefrontend/args.go`**: drop `Envelope`.
- **`internal/openfiletable/open_file_table.go`**: drop `Entry.EnvKeyID` / `Entry.Wrapper`; gains
  `Entry.KeyIdx` (cached beside `ID`, covered by the same `IDLock`).
- **`mount.go`**: delete the `keyPool == -1` CEK bootstrap block (~lines 327–394); the KEK unwrap
  (§4) replaces it. Remove `configfile.EnvSetUpFlag` (`"CEK"`); `file_dir_ops.go` keeps a listing
  filter, now hiding `configfile.KeyRingFileName` (`KR`) alongside `gocryptfs.conf` — the ring sits
  in the cipherdir root, so without it a readdir of the mount would expose an undecryptable name.
- **`internal/tkc/`**: remove the envelope `KMSConnector` interface + `Get()`, `mock_connect.go`
  (envelope bbolt mock), and the envelope consts `EnvelopeIDLength`/`EnvelopeIDAttrName`
  (`user.envID`)/`WrappedKeyAttrName` (`user.wrapped`). `search_connect.go` is **rewritten** (§7),
  not deleted. Keep `NameTransformEnvName`? — no longer referenced once `New` changes; remove.
- **`internal/configfile/config_file.go`**: remove `KeyPool`, `EnvelopeID`, `EnvEncAlg` (config +
  `CreateArgs`); remove `Create`'s `EnvelopeID: uuid.NewString()`. `cli_args.go`: remove `-key-pool`,
  `-env-enc-alg`, the `DefaultEnvAlg` const, and the `keyPool` validation.

Result: the content/filename path is stock gocryptfs fed by one key. `CryptoCore.Wipe()` becomes
meaningful again (there is now a real derived key to drop) — though as built it still only nils the
stdlib cipher refs; see §5.

---

## 4. gocryptfs — KEK lifecycle (init / startup)

Schema (as built, `internal/configfile/keyring.go` — the design put this in `config_file.go` and
§0 round 2 moved it out): `KeyRing{Keys []KeyRingEntry}` in the `KR` file, with
`KeyRingEntry{KeyID string, Ciphertext []byte, CreatedAt time.Time, OpCount uint64}`. `FlagGatewayKEK`
was dropped (§0 round 3 item 3). The ring's read API is a single `Active()`, returning the **newest**
entry and erroring only on an empty ring; writes always use the newest key, so it is also the only
entry a new file header can name. An index-based accessor was tried and removed as unused — the read
path resolves keys through `contentenc.aeadForKey`, never the ring.

**In-memory key store — designed, NOT built.** The design called for a small `map[keyID][]byte` of
unwrapped plaintext keys + the active keyID in `internal/tkc` or `internal/cryptocore`, sized to hold
more than one so Phase 3 would be additive. **As built there is no key store:** `initFuseFrontend`
unwraps the single active ring entry into a local `masterKey`, hands it to `cryptocore.New`, and
zeroizes it immediately (`initFuseFrontend`) — after crypto init the only resident key material is
inside the AEAD/EME ciphers, so nothing needs to be held for the life of the mount. The map becomes
necessary in Phase 3, when per-file keyID markers mean several keys are live at once.

**`-init`** (`initDir` → `configfile.Create`) — **SUPERSEDED 2026-07-31 (see §0): init does NOT
contact the key service.** The design below originally had init `Connect` + generate; as built,
init only resolves the `NodeID` (persisted, so the first mount's generate and every later unwrap
land in the same keyspace) and writes the config — and **no ring file at all**. `Create`
hard-requires a non-empty `NodeID` — `initDir` resolves it, `Create` must not mint a different
one. `configfile` stays free of a `tkc` import; `CreateArgs` carries no `KeyRing`.

**Startup** (`mount.go`, replacing the CEK block): after `tkc.Connect`, `LoadKeyRing(args.config)`
(which derives the `KR` path itself, so no caller can name another filesystem's ring) and branch:

- **No ring file (first mount after -init):** `dk, err := tkc.DataKey().GenerateTKFSDataKey()`,
  append `KeyRingEntry{KeyID: dk.KeyID, Ciphertext: dk.Ciphertext, CreatedAt: now}` and
  `WriteFile()` (atomic tmp+rename, 0400, dir-fsync) **before** the key is used — nothing may be
  encrypted under a key whose ciphertext is not yet recoverable from disk. `dk.Plaintext` then feeds
  crypto init directly; **never** persisted.
- **Ring present:** take the entry via `keyRing.Active()`, then
  `key, err := tkc.DataKey().UnwrapTKFSDataKey(e.KeyID, e.Ciphertext)`.

Either branch passes the plaintext into `cryptocore.New(key, backend, ivBits)`, zeroizing
the local copy right after. On any generate/persist/unwrap error: fail closed with a clear message
(fail-closed is mandatory — a mount that can't get its key must not start).

---

## 5. gocryptfs — key-memory hygiene (Phase-1.5 deferred 2a / 2b)

The design assumed a resident plaintext key + a derived-key cache would exist at unmount, and wired the
Phase-1.5 primitives accordingly. The as-built shape is simpler because neither survives crypto init:

- **2a — as built: zeroize at mount, not at unmount.** The master key is zeroized immediately after
  `cryptocore.New` (`initFuseFrontend`), so there is no resident plaintext key for the `wipeKeys`
  closure (returned by `initFuseFrontend`, deferred in `doMount`) to clear — it only calls `cCore.Wipe()`, which
  still just nils `AEADCipher`/`EMECipher` and forces a GC. Phase-1.5's `cryptocore.WipeCache` was
  left **unwired** here and then **deleted** in round 3 (`wipe.go`/`wipe_test.go`): it only ever
  operated on an `lru.Cache`, and the KEK model has no key cache to purge — the envelope rip took the
  last one, making it the last `tkutils/lru` user. **Still deferred:** making
  `CryptoCore.Wipe()` zeroize the derived EME/content key bytes (today the derived copies are
  zeroized inside `New`, and `Wipe` holds none).
- **2b — `dkc.Close()` on unmount — DONE:** `wipeKeys` calls `tkc.DataKey().Close()` so the connector
  releases its mTLS client / bbolt handle (and, for the real connectors, drops any resident secret).
  It is unconditional now: the `confFile != nil` guard existed only for `-zerokey`, which never
  established a connector, and `-zerokey` is gone (§0 round 3 item 1).

Order in `wipeKeys`: `cCore.Wipe()` → `tkc.DataKey().Close()` (two steps, not three — there is no
key-store zeroize). `security.Memlock()` (`doMount`) already keeps the key out of swap; no change.

---

## 6. gocryptfs — format version bump & validate

- **`internal/contentenc/file_header.go`**: `CurrentVersion` **2 → 3**, and the header grows the
  `KeyIdx` field (§0 round 3 item 4): `HeaderLen` 18 → 20. This is the single version
  source: `ParseHeader`/`Pack` reject non-3 file headers, and `configfile.Create` stamps
  `Version: contentenc.CurrentVersion` while `Validate` rejects any other on-disk version — so
  the bump makes both per-file data and the config fail-closed against v1/v2. (Confirmed single
  source: `grep CurrentVersion`.) Tests that hard-coded ciphertext sizes now derive them from
  `contentenc.HeaderLen`, so the next header change does not silently break them.
- **`internal/configfile/validate.go`**: the version check is the whole format gate — a v1 envelope
  config is rejected by it alone. The design's GatewayKEK gating was added and then removed
  (§0 round 3 item 3): a flag set on every config it ever writes distinguishes nothing. Remaining
  additions: **EMENames requires Raw64** (round 3 item 6), and each ring entry needs a non-empty
  `KeyID` + `Ciphertext` — enforced by `KeyRing.Validate` at load, in keyring.go, not here. A
  **missing** ring file is valid; it is the state -init leaves, consumed by the first mount's generate
  (§0 2026-07-31 redesign; the original design instead required a non-empty ring here).
  Every failure carries the exit code that matches its cause (round 3 item 7).
  Note that dropping the `KeyPool`/`EnvelopeID`/`EnvEncAlg` fields is *not* itself a rejection
  mechanism: `Load` uses a plain `json.Unmarshal` (no `DisallowUnknownFields`), so leftover v1 fields
  are silently ignored rather than refused.
- **`internal/configfile/config_file.go`**: `writeJSONAtomic(filename, v)` is shared by
  `ConfFile.WriteFile` and `KeyRing.WriteFile` — tmp + `O_EXCL` 0400 + fsync + rename + dir fsync,
  with tmp cleanup on failure. Both files hold data a mount cannot recover from if it lands
  truncated, and both are only ever replaced, never edited in place.

---

## 7. Search connector (KEK) + keep `tenantdatakey` route

**gocryptfs `search_connect.go` (rewritten) — `searchConnector` implements `DataKeyConnector`:**
- Keeps the existing ramdisk contract: read `gw.cert.pem`/`gw.key.pem`/`gw.ca.pem` → mTLS client;
  read `gw.token` (tenant token) + `gw.hosts.json` (keep hosts). **As built the old mtime-polled
  reload is gone:** the material is read once in `newSearchConnector`/`load` and the `http.Client` is
  built once (no ticker, no `newClient`). Data-key calls only happen at mount start, so a
  rotated cert is picked up by remounting. An empty CA is rejected (it would otherwise flip
  `InsecureSkipVerify` on), as is an empty host list.
- `GenerateTKFSDataKey`: mint ephemeral transport key (shared helper, §2) → POST
  `https://{host}:7070/keepsvc/tenantdatakey/generate` with `model.TKFSDataKeyGenerateRequest`
  (`NodeID`, `TransportAlg`, `TransportPubKey`) + header `kmsclient.HeaderTenantToken: token` → decode
  `TKFSDataKeyGenerateResponse` → `unwrapTransit(TransitWrappedKey)` → `TKFSDataKey{KeyID, Plaintext,
  Ciphertext}`. Retry across `kmsHosts` (mirror the old `fetchKey` host-shuffle loop).
- `UnwrapTKFSDataKey`: POST `.../tenantdatakey/unwrap` with `TKFSDataKeyUnwrapRequest` →
  `unwrapTransit`. `Close()`: `CloseIdleConnections()`.
- The keyspace for search: keep derives the **tenant** from the client-cert `StreetAddress`; the
  request `NodeID` scopes within it. (Search's NodeID is the gocryptfs `NodeID` from `gocryptfs.conf`.)

**keep — new `web/tenantdatakey.go`** (as-built; mirrors `web/tenants_ek.go` route/manager/header pattern and
`web/tenants_crypt.go`'s recipient-pubkey wrap):
- **`POST`** `/keepsvc/tenantdatakey/generate` and `.../unwrap`, both wrapped in `gatewayOperation`
  (tenant-token validated against the mTLS cert DN — same auth as `tenantek`).
- generate: `tenantID` from the **client cert** (`tenants.ProcessRequest` → `StreetAddress`), NOT the
  injectable `TenantID` header (finding #3); `pt, ct, id := TenantManager.KekWrap(tenantID, nodeID)`;
  transit-wrap `pt` to the request's `TransportPubKey` under `TransportAlg` → `wrappedKey`; respond
  `TKFSDataKeyGenerateResponse{KeyID: id, Ciphertext: ct, TransitWrappedKey: wrappedKey}`. Zeroize `pt`.
- unwrap: `pt := TenantManager.KekUnwrapScoped(tenantID, req.NodeID, req.KeyID, req.Ciphertext)` — the
  **new** 4-argument scoped variant, which refuses a `KeyID` that is not the KEK currently associated
  with the request's `NodeID` and fails closed when there is no association at all. Then transit-wrap
  → respond `TKFSDataKeyUnwrapResponse{TransitWrappedKey}`. Zeroize `pt`. (The unscoped 3-argument
  `KekUnwrap` is deliberately *not* used on this route: it would unwrap any KEK in the tenant.)
- **path/keyspace mapping:** `KekWrap`/`KekUnwrapScoped` take a `path`/`keyspace` string that derives
  the KEK association. As built it is the bare request `NodeID`, no prefix — stable across generate and
  unwrap for the same filesystem. Caveat carried from §0: `NodeID` is self-asserted and travels in the
  same `gocryptfs.conf` as the `KeyID`/`Ciphertext`, so the scoping is a barrier only against callers
  whose keyspace *differs*; the cert-derived tenant is the hard boundary here.
- **transit-wrap helper (server side) — as built:** call the shared
  `model.TransitWrap(req.TransportAlg, req.TransportPubKey, pt)`, which allow-lists the algorithm
  (`transitAlgBits`: RSA-2048/3072/4096), parses the PEM via `certutil.ParsePublicKey` and
  RSA-OAEP/SHA-256-encrypts with a nil label — the exact inverse of the client's `model.TransitUnwrap`.
  The sharing question is settled: keep, gatehouse *and* the gocryptfs test all call this one helper
  (the test's `wrapForTransport` is now a one-line delegation to it), so nothing is triplicated and no
  reference implementation lives in a test.
- Crypto already exists (`KekWrap`/`KekUnwrap`, `kek.AES256_GCM`, 32-byte keys); this is additive
  routing + wrapping + one new manager method (`KekUnwrapScoped`) + tests. `tenantek` envelope routes
  stay untouched (lizard warm/S3 + bbolt still use them).

---

## 8. gatehouse — un-stub the default data-key handlers

`management/tkfsdatakey.go:209,257` (`tkfsdatakeyGenerate`/`tkfsdatakeyUnwrap`) — implemented this pass
(they were 501 stubs); no `StatusNotImplemented` remains in the file. The design below is what they do:
- Parse the `model.TKFSDataKey*Request`; DN from the verified client cert (`auth.ParseCredentials`),
  `NodeID` from the body; keyspace = **DN + NodeID** (`tkc.Keyspace(dn, nodeID)` equivalent — mirror
  gocryptfs `internal/tkc/gateway.go` `Keyspace`).
- generate: `resp := oec.Get().KekWrap(tenantID, &model.KekWrapRequest{... keyspace ...})` →
  `KekWrapResponse{Key, WrappedKey, WrapperID}` (Key = plaintext, WrappedKey = KEK-ciphertext,
  WrapperID = kek id). Transit-wrap `Key` to the request `TransportPubKey` → respond
  `TKFSDataKeyGenerateResponse{KeyID: WrapperID, Ciphertext: WrappedKey, TransitWrappedKey: transitWrapped}`.
  **Name mapping was the trap, and the client field has since been renamed to fix it:** keep/oec's
  `WrappedKey` (KEK-ciphertext) is the client's `Ciphertext`, while the transit-wrapped plaintext was
  *also* called `WrappedKey` on the client response — two different `[]byte` values one identifier
  apart, so swapping them compiled. The client field is now `TransitWrappedKey`, and the rule is that a
  bare wrap/unwrap always means the KEK layer while anything per-call carries a `Transit`/`Transport`
  qualifier. keep/oec's own `WrappedKey` keeps its name.
- unwrap: `oec.Get().KekUnwrap(...)` → plaintext → transit-wrap → `TKFSDataKeyUnwrapResponse{TransitWrappedKey}`.
  The `Mount` (keyspace) sent here is load-bearing: keep routes `ServiceTKFS` unwrap on to
  `KekUnwrapScoped`, which only recovers the key if the requested `KeyID` is the KEK that keyspace
  currently owns. That binds the cert-derived DN half; the `NodeID` half is self-asserted.
- Zeroize plaintext after wrapping. Add real handler tests (round-trip via the mock oec/keep if one
  exists; else httptest against a fake oec).

The `tenantID` the gateway uses for `oec` is, as built, `config.Get().TenantID` — the gateway's own
tenant, matching the existing `WrapFor`/`Unwrap` path (open-Q2).

---

## 9. tkutils, lizard, migration

- **tkutils:** reuse `model.TKFSDataKey*` (already merged, `e0ac85e`). The sharing question was
  decided in favour of sharing: this phase added `model.ServiceTKFS` and `model/transit.go` —
  `NewTransportKey`/`TransitWrap`/`TransitUnwrap` plus the `transitAlgBits` allow-list, using
  `certutil` for PEM handling and `kem.KemType` *only* as the wire discriminator (the wrap itself does
  not go through the `kem` package). keep + gatehouse are re-pinned to the merged module
  (`v2.16.1-0.20260730203651-829a3f44f5e6`); the "no tkutils change → no re-pin" branch is moot.
- **lizard:** none. `encfs.go` exec seam (`-init -search`, `-search -fg`) and `standard_connector.go`
  ramdisk provisioning are unchanged; the KEK switch is entirely inside the gocryptfs binary, and the
  connector already writes the ramdisk certs before gocryptfs launches (`main.go:151-153` before `:202`).
- **migration:** v1↔v2 incompatible by design. Runbook (Phase 5): run old binary to mount v1, new
  binary to mount fresh v2, `cp -a` plaintext across. TrustedSearch: same, applied to the `idxcipher`
  volume (its index is also rebuildable from source if preferred). Warm/S3 + bbolt stay envelope
  (not part of this migration).

---

## 10. Testing strategy

- **Unit (gocryptfs):** KeyRing round-trip + the `Validate()` **accept** path
  (`internal/configfile/keyring_test.go`); `cryptocore.New(key,...)` derivation determinism and the
  encrypt→decrypt round trip through the unified AEAD (`internal/cryptocore/`, `internal/contentenc/`);
  connector generate/unwrap round-trips against httptest fake servers and the bbolt mock
  (`internal/tkc/gwconnect_test.go`, `mock_gwconnect_test.go`). Run under `-race`.
- **Integration (gocryptfs, real FUSE — `tests/tkfs_kek/`, 8 tests):** what the design listed as unit
  tests actually landed here, driven through the real binary against the **mock gateway** (`-mock-kms`,
  no live service): `-init` writes a v3 config and **no** ring file; the first
  mount persists a single ciphertext-only `KR` entry (asserted against the marshaled file, mirroring
  the Phase-1.5 base64 lesson); first-mount generate → write → unmount → remount (unwrap) → read;
  the ring file is hidden from a readdir of the mount; a first mount whose persist fails serves no
  I/O; a first mount under `-ro` is refused; and the harness-injected `-mock-kms` default.
- **Integration (gocryptfs, `tests/cli/healthcheck_test.go`):** the endpoint answers once the mount
  signals ready (no sleep — if one were needed, the bind/ready ordering would be wrong); a busy port
  is fatal with exit 31 **and** leaves the mountpoint clean; a negative port disables it. The 0-means-
  unset mapping is a unit test (`TestResolveHealthCheckPort`) rather than an integration one, since
  binding the default port would collide with the other suites. Note the busy-port
  squatter has to bind the **wildcard** address: Go sets `SO_REUSEADDR`, so a loopback-only listener
  does not conflict with the mount's wildcard bind and the mount comes up alongside it.
- **Unit (keep):** `tenantdatakey` generate→unwrap round-trip via `TenantManager`; `KekUnwrapScoped`
  rejects a KeyID the keyspace does not own and fails closed with no association at all; tenant-token
  auth reject; no-plaintext-on-wire (assert the base64 wire form, not the decoded bytes). Both
  directions of the transit wrap now come from the one shared `model/transit.go` (covered by tkutils'
  `model/transit_test.go`), so there is no independent client implementation left to cross-check.
- **Unit (gatehouse):** un-stubbed handler round-trip; DN-ACL still enforced; name-mapping correctness
  (Ciphertext vs TransitWrappedKey).
- **Integration / E2E (all four, the "all repos together" gate):** live `gocryptfs -init` →
  `-fg` mount → write/read → unmount → remount decrypts, against a real gatehouse+keep (default mode)
  **and** a keep `tenantdatakey` (search mode). This is the phase's definition of done.
- **`Validate()` reject cases — now covered** by `TestValidateExitCodes`, which asserts not just
  *that* a bad config is refused but that the **exit code matches the reason** (wrong version →
  `DeprecatedFS`, self-contradictory → `LoadConf`); conflating the two told operators to migrate a
  filesystem that was merely corrupt. `TestCryptoCoreDerivesDistinctKeys` pins that the EME and
  content keys differ from each other and from the master key. `keyring_test.go` covers the absent-vs-
  zero-length distinction and that `Active()` returns the newest entry.

---

## 11. Threat-model note (recorded from the 2026-07-27 discussion)

The KEK model does **not** protect against a full compromise of an authorized, running box — the
plaintext key is in process memory, and the certs+token can replay `generate`/`unwrap`. This is
inherent to any design where a node decrypts its own data, and is no worse than the envelope model.
What it *does* buy: (a) **disk theft alone is useless** (the `KR` file holds only KEK-ciphertext;
ramdisk certs are tmpfs); (b) **revocation** via keep/gateway ACL on next mount; (c) **no plaintext
key at rest** — the `KR` file that replaced the envelope model's `CEK` is ciphertext-only, and
nothing in either file is usable without the key service. Transit-wrap defends the wire/logs, not
the endpoint. The lever against
*stolen-certs-used-elsewhere* is **instance binding (Phase 4)**; not pulled forward unless
prioritized for search.

---

## 12. Sequencing, branches, definition of done

- Branches (per-repo `feature/tkfs-v2-phase2-*` off each repo's `feature/tkfs-v2`, squash-merged back):
  - gocryptfs: `feature/tkfs-v2-phase2-kek-lifecycle` (worktree created).
  - keep / gatehouse / tkutils: phase-2 worktrees all created and their slices landed — the shared
    helper did land, and tkutils' `model/transit.go` is merged and pinned by keep + gatehouse.
- Build order that stays green at each step:
  1. gocryptfs core rework + KEK wiring against the **mock gateway** (self-contained; full unit tests).
  2. gatehouse handlers + keep `tenantdatakey` route (independent repos, parallelizable).
  3. Live E2E across all four; then squash-merge each repo's phase branch.
- **Definition of done:** all four repos build + test green (`-race` where crypto); live E2E generate/
  unwrap works in both default and search modes; `-init` writes no key ring and the first mount
  persists ciphertext-only (2026-07-31 redesign); version bumped to 3 and the header carries `KeyIdx`;
  the master key is zeroized right after crypto init and unmount drops the
  ciphers (`CryptoCore.Wipe()`) + closes the data-key connector (zeroizing derived key bytes inside
  `Wipe()` is deferred); Copilot review addressed; the user's review rounds addressed (§0 — three
  applied 2026-08-03/04); TK-1392 → Done.
- **Not yet committed.** The whole gocryptfs slice is still an uncommitted working tree, and three
  temporary `replace` directives point at a local tkutils worktree because `model.TKFSKeyspace` is
  unpushed. Those must come out — push to tkutils PR #79, re-pin, re-verify — before any commit.

---

## 13. Open questions / risks

1. **keep keyspace prefix** — **PARTLY RESOLVED (§0):** KEK `path` = request `NodeID`, no DN prefix on
   the keep route. Cross-tenant isolation comes from the client cert, and within a tenant unwrap is
   additionally narrowed by `TenantManager.KekUnwrapScoped` to the KEK the claimed keyspace currently
   owns (fail closed if it owns none). **Still open:** within a tenant that is not a barrier — the
   `NodeID` is in `gocryptfs.conf` and the `KeyID`/`Ciphertext` in the `KR` file beside it, so anyone
   who can read one can read both and replays the
   whole triple faithfully (`TestKekUnwrapScopedDefeatedByFaithfulReplay`). Splitting the ring out of
   the config changed nothing here — both live in the cipherdir. Closing it needs an
   authenticated `NodeID` or a per-filesystem secret kept out of the config — no check over
   self-asserted values can do it. Tracked with the epic-level NodeID-isolation reassessment.
2. ~~**gatehouse `oec` tenant context**~~ **RESOLVED (§0):** the data-key listener uses
   `config.Get().TenantID` (the gateway's own tenant), matching the existing `WrapFor`/`Unwrap` path.
3. ~~**Transit-wrap helper home**~~ **RESOLVED (§0):** one shared `model/transit.go` in tkutils owns
   both directions. keep + gatehouse call `TransitWrap`; the client calls `NewTransportKey` +
   `TransitUnwrap` (its `unwrapTransit` is now a thin wrapper that only adds the 32-byte length
   check), and the gocryptfs test's `wrapForTransport` is a one-line delegation to `model.TransitWrap`
   — so the test drives the production path rather than acting as an independent cross-check.
4. ~~**`cryptocore.New` blast radius**~~ **RESOLVED:** four call sites — `initFuseFrontend` plus three
   package tests (`internal/contentenc`, `internal/fusefrontend`, `internal/nametransform`) — all on
   the new `New(key, aeadType, IVBitLen)` signature (`useHKDF` dropped in §0 round 3).
   `internal/speed` was never a caller: it
   uses only the `cryptocore.Backend*` constants and builds its own ciphers.
5. ~~**`-init` failure semantics**~~ **RESOLVED, then SUPERSEDED (§0 2026-07-31):** `-init` no
   longer touches the key service, so an unreachable key service cannot fail init at all; it
   surfaces at the first mount instead, which fails closed before anything is encrypted (the
   ciphertext is persisted via atomic `WriteFile` before the key is used).
6. **Rebuildability of the TrustedSearch index** — not needed for `cp` migration, but flagged: the
   lizard "re-build index ability" is a TODO; `cp -a` is the safe path regardless.
7. **Symlink targets and xattr values have no file header** (surfaced by the round-3 `KeyIdx` work).
   They are encrypted like a content block, so on decrypt there is nothing to tell them which key was
   used and they assume the write key. That is exact while the ring holds one entry, and it is a
   **Phase-3 blocker**: rotation must either re-encrypt them or record the index beside the value.
   The envelope model solved this by storing its per-file key id in a plain (unencrypted) xattr next
   to the value, so the precedent exists and the index is not secret. Noted in code on
   `decryptSymlinkTarget`.
