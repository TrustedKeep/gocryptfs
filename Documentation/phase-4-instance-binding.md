# Phase 4 — Instance identity + binding (TK-1394)

Pairs each TKFS instance with the EC2 instance it runs on, so its client certificate and `KR` file,
copied to another machine, stop working there. Spans tkutils (types, verification, IMDS fetch), gatehouse
(verification, enforcement, the requirement flag, admin proxy routes), keep (binding store, identity
certificates, admin routes) and gocryptfs (fetching and attaching the proof). The operator UI is Phase 5
(TK-1434).

## 0. Settled decisions

- **The proof is EC2's `rsa2048` signature** (IMDS `/latest/dynamic/instance-identity/rsa2048`): a
  PKCS#7 SignedData, RSA-2048 over SHA-256, carrying the instance-identity document. It is the variant
  FIPS 140 approves for verification, and it verifies under `fips140=only`. The older base64
  `signature` uses a 1024-bit AWS key and the `pkcs7` variant DSA/SHA-1; neither is accepted.
- **The gateway checks binding.** Binding is a gateway concern, so gatehouse verifies the proof
  (`awsidentity.Verify`, offline), reads the instance's binding from keep, and refuses there. keep does no
  binding work on any call, and `-search`, which reaches keep with no gateway in front, is untouched: its
  connector sends no proof.
- **Validation certificates are admin-added, none built in**, as in TrustedBoundary (which seeded two and
  had admins add their region's): `TKFSPolicy.IdentityCerts` in keep, one AWS RSA-2048 certificate per
  region the fleet runs in, ISO partitions included. Every gateway refreshes them every 10 seconds. Keys
  under 2048 bits are refused, and a certificate the proof carries itself is never trusted.
- **The requirement is gatehouse startup config, `UserData.TKFSRequireBinding`, off by default** (docker:
  `TKFS_REQUIRE_BINDING`, from Phase 5), so it is per gateway. A mixed or rolling fleet enforces only on
  the gateways with the flag; a tenant-wide lease was deferred (§8).
- **Binding and `-sharedstorage` are incompatible**, since a binding pins a filesystem to one machine.
  TKFS reports `SharedStorage` on generate, unwrap and heartbeat, and a gateway requiring binding
  answers it 409 before anything else. TKFS exits 35 (`SharedStorageRefused`) at mount, and on the
  heartbeat, rekey or op-counter rotation that first reaches such a gateway.
- **A pairing is permanent, automatic, and made only where binding is required.** A gateway with the
  flag checks that every call proves a machine and looks up its instance's pairing; where there is one,
  the machine must match. Only a mint, with the machine minting it, or an unwrap of an unpaired
  instance, with the machine unwrapping it, makes one, since an unwrap needs a ring entry; any other
  call naming an unpaired instance is refused. A rotation in particular hands out a fresh ring entry,
  so letting it through would let any ACL'd caller knowing a victim's `InstanceID` unwrap that entry and
  pair the victim with their own machine for good. A mount running when the flag goes on was never
  paired, so it exits 33 at its next heartbeat, and the unwrap of its remount pairs it. The gateway also
  refuses a call proving no machine or another one, and a mint or unwrap whose pairing it cannot save; it
  writes a
  pairing only after keep has authorized the call. Nothing moves or removes a pairing; there are no
  admin binding writes. A gateway without the flag reads and writes no pairing at all.
- **A pairing is its own keep object** (`tkfsb/<instanceID>`), not a field of the heartbeat-rebuilt
  registry record, and deleting the record keeps it.
- **The machine is `AccountID + Region + CloudInstanceID`** (`TKFSHost.SameMachine`). `CloudInstanceID`
  is the EC2 `i-…` id, named apart from the TKFS `InstanceID` (the KEK id). `ImageID` and `PrivateIP`
  are shown to admins and take no part in matching.
- **Refusals are logged where they happen**, at the gateway, with the DN, NodeID, InstanceID and the
  machines involved. There is no conflict preview, and removing an identity certificate is not guarded:
  behind a gateway requiring binding, the instances it verified are refused from their next call.
- **`-mock-aws` proves a fake machine** (account `000000000000`) made for testing and signed by a
  discarded key; a dev tenant adds `awsidentity.MockCertPEM` like any other certificate.
- **A refusal at mount exits 33**: the ring unwrap runs before the first heartbeat, so `ErrDenied` there
  now exits `Revoked` rather than 11, as a refused heartbeat does. The `-sharedstorage` refusal exits 35
  wherever it lands, an unwrap of any ring index included (never a hole); a ctlsock rotation only
  returns it, and the next heartbeat ends the mount.

Considered and dropped: an account mode and an account allowlist (the goal is limiting data access, and
losing a pairing on an ASG replacement is acceptable); built-in AWS certificates; STS
`GetCallerIdentity` (see §8); checking in keep (it would reach `-search` too); a tenant-wide admin switch;
bindings naming several machines; a conflict preview (the UI shows each instance's machine beside its
pairing); admin bind, move and unbind (a pairing is permanent); refusing an unpaired instance until an
admin pairs it; blocklist entries naming a machine (`CloudInstanceID`).

## 1. What it buys, and what it does not

**Closes:** a stolen client certificate plus a copied cipherdir used, through a gateway requiring
binding, on any machine but the paired one. The thief can replay the ring but cannot make IMDS
elsewhere sign a document naming the paired machine.

**Does not close:**

- **Replay by anything that can read IMDS on the paired machine** — code on the host, a container whose
  hop limit allows it, an SSRF to `169.254.169.254`. The signed document is static and carries no nonce.
  cloud-init's EC2 datasource also caches the `dynamic/instance-identity` tree under
  `/var/lib/cloud/instance/` (confirm on the fleet AMI), so a snapshot or AMI of the paired machine's
  *root* volume carries a proof that never expires.
- **Trust on first use.** Behind a gateway requiring binding, a mint pairs with whatever machine made
  it, and an unpaired instance with the first authorized unwrap proving a machine, which needs a ring
  entry as well as an ACL'd certificate. A gateway without the flag still rotates an unpaired instance
  for any ACL'd caller, so in a mixed fleet the entry it hands out can be unwrapped through one with the
  flag to squat that instance.
- **`cp -a` on the paired machine** stays paired with it, as in Phase 3 §12.6.
- **Moving a filesystem.** A pairing cannot be moved, so a filesystem whose instance is replaced is
  refused by a gateway requiring binding until it is re-minted.
- **A gateway without the flag** (a mixed ASG, a rolling change) holds no call to a pairing and makes
  none.
- **`-search` mounts** are never paired or held to anything.
- **A `-search` node's keep credential is gateway-class**: whoever holds it can call keep's policy and
  binding routes directly, as it already could the ACL, blocklist and trusted CAs. It lives on tmpfs.
- **Hosts that cannot prove anything** — off EC2, Fargate, a container on an instance with IMDSv2
  required and a hop limit of 1 — are refused by a gateway requiring binding.

## 2. Wire

`model.TKFSIdentityProof{PKCS7 []byte}` rides as `Identity` (omitempty) on the gateway route's
`TKFSDataKeyGenerateRequest`, `TKFSDataKeyUnwrapRequest` and `TKFSHeartbeatRequest`, beside
`SharedStorage bool` (omitempty). It stops at the gateway. What reaches keep is `Host *TKFSHost`
(omitempty), the machine the gateway verified, on the heartbeat's `TKFSInstance`, for the admin view.
keep records it on the registry record, and drops it on the `-search` route, where no gateway asserts
one. It sets the record's `Route` (`gateway` or `search`) itself, from the door the heartbeat came
through. The gateway refuses `-sharedstorage` with a 409, which no other data-key answer uses (keep's
own 409s reach an instance as 502).

`TKFSBinding{InstanceID, Host, BoundAt}`.

## 3. gatehouse — verification and enforcement

`awsidentity.Verify(proof, certs)` refuses outright when no certificate is usable or the proof is over
8 KiB (BER decoding is quadratic in nesting depth; EC2's is about 2 KiB). It then parses the PKCS#7,
requires exactly one SHA-256 signer, verifies it against the certificates (RSA-2048 or larger),
and parses the signed content (`accountId`, `region`, `instanceId` required). On every data-key call,
after the `-sharedstorage` refusal, the gateway:

1. verifies, which needs no keep call; a heartbeat records the machine, or none, either way. Without the
   flag it stops here;
2. with the flag: no machine → 403, except a proof checked before the gateway has loaded its identity
   certificates → 502; for a named instance (not a mint), reads its pairing from keep: a read failure
   → 502, another machine → 403, an unpaired instance on any call but an unwrap → 403;
3. calls keep with the DN and NodeID, and keep applies the ACL and blocklist;
4. with the flag, after keep succeeds, pairs a mint, or an unwrap of an unpaired instance, with the
   machine it proved (`POST tkfsbinding/:id`, which keep refuses with 409 for an instance already
   paired); a failure is a 502 and the key is zeroized.

Without the flag binding adds no per-call keep traffic. With it, each call naming an instance costs one
pairing read, and each pairing one write. A refused call stops before keep's ACL (step 3), so it is not
recorded.

## 4. Admin API

keep (tenant from the gateway's cert, `gatewayOperation`), proxied by gatehouse under `RequireAdmin`,
query strings and bodies unchanged:

| gatehouse `/api/v1/…` | keep | Result |
|---|---|---|
| `POST tkfsdatakey/identitycert` (PEM cert or chain) | `POST tkfspolicy/identitycert` | 200 `[]fingerprint`; 400 (not RSA-2048+) |
| `DELETE tkfsdatakey/identitycert/:fp` | `DELETE tkfspolicy/identitycert/:fp` | 204; 404 |
| `GET tkfsdatakey/bindings` | `GET tkfsbinding` | 200 `[]TKFSBinding` |
| `GET tkfsdatakey/binding/:instanceID` | `GET tkfsbinding/:instanceID` | 200; 404 |

The gateway itself uses keep's `GET tkfspolicy/identitycert` (the certificates, `{}` for none) and `POST
tkfsbinding/:id`, neither proxied.

## 5. gocryptfs — fetching and attaching

`tkutils/awsidentity.Fetch` reads the `rsa2048` signature with aws-sdk-go-v2's `feature/ec2/imds`
client, which takes an IMDSv2 token when it can and falls back to IMDSv1, retrying as the SDK does; the
only change to its defaults is no proxy. The gateway connector holds a `machineIdentity`, fetched on the
first key-service call with a 5-second bound, which covers the SDK's retries (a hop-limited container
falls back in about 3.5 seconds, and off EC2 a lookup fails in about 4 seconds where the address is
refused, or runs into the bound where packets are dropped). The answer, success or failure,
is kept for the mount's life: the SDK already retries within the lookup. The proof rides generate,
unwrap and heartbeat; without one the calls go out anyway, and a gateway requiring binding
refuses them — exit 33 at mount, immediate unmount on a later heartbeat. The search connector and
`-mock-kms` send no proof.

`tkc.Connect` takes `-sharedstorage`, and the gateway connector reports it on every call and maps a
409 to `ErrSharedStorageRefused`, which wraps `ErrDenied` (so an unwrap does not retry it and a
heartbeat does not count it as a strike). It exits 35 from the mint, the unwrap of any ring index, the
first heartbeat, a later heartbeat (`shutdownNow`), and a rotation by the op counter or a rekey. One
helper, `keyServiceExit`, picks every such exit code: 35 for this refusal, 33 for any other (a refused
rotation included, which exited 34 before Phase 4), and the caller's code otherwise. `-search` and
`-mock-kms` never see the refusal.

## 6. Operator procedure

1. Every gateway, keep node and TKFS client runs a Phase-4 build. A keep without the identity
   certificate and binding routes gives a gateway nothing to verify with, so one requiring binding
   refuses every call.
2. Add the AWS RSA-2048 certificate for each region the fleet runs in (AWS: "AWS public certificates
   for instance identity document signatures", **RSA-2048**; ISO partitions publish theirs in-partition).
3. Watch the instance list: every instance that heartbeats from a covered region gains a `Host`. One
   without one is what enforcement would refuse. Pairings form only once a gateway requires binding,
   each at its instance's mint or first authorized unwrap through it.
4. Remount every `-sharedstorage` filesystem without the flag, or keep it behind gateways that will not
   require binding. Then set `TKFSRequireBinding` on every gateway and restart them; until all have it,
   only some calls are held to it. Every mount already running was never paired, so it exits 33 at its
   next heartbeat through such a gateway; remount each one by hand (step 5 keeps systemd from doing it),
   and its unwrap pairs it. Where no containerized mount needs the IMDSv1 fallback, require
   IMDSv2 with a hop limit of 1, which narrows who on the host can read the proof.
5. Run mounts under systemd with `RestartPreventExitStatus=33 35`.

## 7. Testing

- tkutils: a valid signature; refusal of another signer (even one carrying its own certificate), a
  tampered document, SHA-1, a 1024-bit signer, a proof over 8 KiB that would otherwise verify, non-RSA
  certificates, garbage; a document naming no machine; EC2's BER encoding (its captured DSA `pkcs7`
  parses and is refused for SHA-1); the mock verifying only against its certificate; `Fetch` against a
  fake IMDS serving the mock (IMDSv2, the v1 fallback, a token request that never answers, failure).
  The package passes under `GOFIPS140=v1.0.0 GODEBUG=fips140=only`; no CI job runs it that way yet. No
  test yet verifies a real EC2 `rsa2048` signature.
- gatehouse: with the flag, the paired machine is admitted on generate, unwrap and heartbeat; a mint and
  an unpaired instance's unwrap are paired with the machine they proved, after keep authorizes them; an
  unpaired instance's heartbeat and rotation are refused before keep;
  another machine, no proof and an unverifiable one are refused before keep authorizes or records them,
  and a proof checked before the identity certificates load is a 502; an unreadable or unsavable pairing
  is a 502 with any key zeroized; the heartbeat records the machine; without the flag nothing is refused
  and no pairing is read or written; the `-sharedstorage` 409, only with the flag; the identity
  certificate refresh; no admin route writes a pairing; every admin route is registered, admin-only,
  escaped, and passes query, body, keep's status and Content-Type through.
- keep: the search route never pairs or records a `Host`, and keep sets `Route`, which no caller can; the
  heartbeat records the gateway's `Host`; attach refuses an instance already paired, and no route moves
  or removes one; an undecodable pairing is an error; the certificate list; no route reads a tenant from
  the header; pairings surviving a record delete.
- gocryptfs: the proof and `SharedStorage` ride generate, unwrap and heartbeat on the gateway connector;
  the connector is built with both; a 409 is `ErrSharedStorageRefused` and a 403 is not; it exits 35 at
  the first heartbeat, on a later one and on the report after a rekey, and `keyServiceExit` maps a
  refused rotation to 35 or 33; the lookup runs once, bounded, and a failed one sends none.

## 8. Designed for later

- **Freshness.** A presigned `sts:GetCallerIdentity`, which the gateway can check, proves the instance
  role with minutes of freshness and needs no certificates.
- **A tenant-wide requirement.** A lease in keep that every gateway renews would hold every call to
  binding once any gateway requires it, closing the mixed-fleet gap in §1.
- **Caching pairings in the gateway**, should the per-call read show up in mount times.
- **Other clouds** (GCP/Azure identity tokens) are a second verifier beside `awsidentity.Verify`.
