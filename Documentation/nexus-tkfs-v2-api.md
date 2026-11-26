# Nexus TKFS data-key API, v1

What a TKFS v2 `-search` mount expects from Nexus when lizard's ramdisk selects it. The client is gocryptfs `internal/tkc/search_connect.go`. The wire types are tkutils/v2 `model` at dc83a59, used unchanged.

## Selecting Nexus

lizard writes these files to the TrustedSearch ramdisk. gocryptfs reads them once, at mount.

| file | keep mode (unchanged) | Nexus mode |
|---|---|---|
| `gw.provider` | absent, or any value other than `nexus` | `nexus`, whitespace-trimmed |
| `gw.hosts.json` | `["host"]`; the client appends `:7070` | `["host:port"]`, used as given, e.g. `nexus:9082` |
| `gw.cert.pem`, `gw.key.pem`, `gw.ca.pem` | mTLS; an empty CA is fatal | same |
| `gw.token` | sent as `X-TrustedKMS-Token` | not read, not sent |
| `gw.namespace` | not read | optional; when non-empty, sent as the `Namespace` header |

If `gw.provider`, or in Nexus mode `gw.namespace`, exists but cannot be read, the mount fails before it contacts anything. Without a namespace the client sends no header and Nexus uses its `default` namespace, as v1 did. lizard writes its configured namespace there from the release that adds it; older lizards write none.

- **keep:** `POST https://<host>:7070/keepsvc/tenantdatakey/<op>`
- **Nexus:** `POST https://<host:port>/tkfsdatakey/<op>`

`<op>` is `generate`, `unwrap` or `heartbeat`. Request bodies are the same in both modes.

## Routes

Nexus serves the routes on its search listener (the `[search]` port), at the root next to `/envelopekey/*`, under the existing SEARCH module.

- Each route takes a POST with an `application/json` body and answers 200 with JSON on success.
- The shapes are `TKFSDataKeyGenerateRequest/Response`, `TKFSDataKeyUnwrapRequest/Response` and `TKFSHeartbeatRequest/Response`. `[]byte` travels as base64 and `time.Time` as RFC 3339.
- A body larger than 64 KiB gets 400.
- Any other `/tkfsdatakey/*` path gets 404, so it is never proxied to lizard.

**Auth, on every route:**

1. The client presents its mTLS cert, verified against Nexus's client-CA bundle. The Nexus user `lower(cert CN)` must exist; if not, the answer is 401.
2. The namespace comes from the `Namespace` header, or is `default` without one. It must exist and must not be `tkc_internal`.
3. The subject must be in `[search].systemsubjects`, and `lower(peer CN)` must equal the subject.
4. The DN is `tcutils.SanitizeDN(tcutils.CertificatesToClientDN(r.TLS))`. A Blocklist match on `(DN, NodeID, KekID)` gets 403. The Blocklist is the only part of the policy that is enforced.

A failure in step 2 or 3 gets 403.

**generate:** answers 400 if `NodeID` or `TransportPubKey` is empty (the request's `Validate`). `Identity` and `SharedStorage` are ignored.

- With an empty `KekID`, the blocklist is checked with an empty `KekID`, then the transport key (400 if unusable), and only then does Nexus mint a new AES256-GCM KEK under a fresh uuid, so a refused mint stores nothing.
- With a `KekID`, Nexus loads that KEK. A KEK not in the caller's namespace gets 503 (`model.ErrUnknownTKFSKek`), never 404, which the client reads as a missing route; keep does the same.
- Nexus then wraps a fresh data key and stamps `CreatedAt` after the wrap. A transit-wrap failure gets 400.
- The response is `{KeyID, Ciphertext, TransitWrappedKey, CreatedAt}`. The client refuses a response with a zero `CreatedAt`, an empty `KeyID` or `Ciphertext`, or, on a rotation, a `KeyID` other than the `KekID` it sent.

**unwrap:**

- 400 if `NodeID`, `KeyID`, `Ciphertext` or `TransportPubKey` is empty (`Validate`), or if the transit wrap fails.
- The blocklist is matched on `(DN, NodeID, KeyID)`.
- 503 if the KEK is not in the caller's namespace, for the same reason.
- 500 if the GCM unwrap fails.
- The response is `{TransitWrappedKey}`.

**heartbeat:**

- 400 if `NodeID` or `KekID` is empty (`Validate`).
- An `unmount` skips the blocklist; any other beat is matched on `(DN, NodeID, KekID)`.
- A KEK not in the caller's namespace gets 503, before anything is recorded, `unmount` included.
- Nexus files the instance record `{ID, NodeID, DN, KekID, KeyIdx, KeyCreatedAt, Route:"search", FirstSeen, LastMounted, LastUnmounted}` under `(KekID, ID)`, where `ID` is `model.TKFSInstanceID` of DN and NodeID. The record is merged by `model.MergeTKFSHeartbeat`, as on keep: `mount` sets `LastMounted`, `unmount` sets `LastUnmounted`, and it is written only when the instance appears, mounts, unmounts or changes key. An unparseable record is replaced; an `unmount` of an unknown instance records nothing.
- An `unmount` always gets `{}`. Any other beat gets `{"Command":"rekey"}` while that instance's directive is outstanding for `(KeyIdx, KeyCreatedAt)`, and `{}` otherwise. Nexus never clears the directive, and one it cannot read is logged and costs the beat its command, not the beat.

## Status codes and what the client does

The status mapping is the same as in keep mode, and unit tests in `search_connect_test.go` cover it.

| status | client reads | effect on the mount |
|---|---|---|
| 200 | success | a heartbeat resets the failure count |
| 403 | `ErrDenied`, returned at once | a refusal: fails a mount that is starting and suspends a running one; unwrap is not retried |
| 401 | `ErrUnauthenticated`, returned at once | fails a mount that is starting; a running mount counts it as a missed heartbeat, and three in a row suspend it |
| 404, 501 | the client tries the next host; `ErrNotImplemented` once every host answered so | fails a mount that is starting; a running mount counts it as a missed heartbeat; a rotation exits 34 |
| anything else, or a transport error | an outage; the client tries the next host | once every host has failed, the same as 401 |

409 is the gateway's `-sharedstorage` refusal. Nexus never returns it, and this client would read it as an outage.

## Storage and admin

- **Storage.** Nexus's sealed KVS holds, under `<ns>/search/tkfs/`: `kek/<kekID>`, a `model.TenantKek` in keep's record format; `instance/<kekID>/<id>` and `rekey/<kekID>/<id>`, one per instance, so mounts sharing a KEK (`-sharedstorage`) keep a record and a directive each; and `policy`. Each segment is path-escaped. A mint is a fresh uuid, so it needs no lock.
- **Admin.** The admin port, under RequireAdmin, serves `/api/search/tkfs/{namespace}/...`. An unknown namespace gets 404 and `tkc_internal` 400.
  - `GET instance` lists the records as `{"instances":[...]}`.
  - `POST instance/{kekID}/{id}/rekey` files a directive against the `KeyIdx` the instance last reported, at Nexus's time now, replacing any pending one. It answers 202 with the `TKFSRekeyDirective`, or 404 if there is no record.
  - `DELETE instance/{kekID}/{id}` deletes the directive, then the record, and keeps the KEK; the instance's next heartbeat registers it again. It answers 204, or 404 if there is no record. Existence is checked without reading the record, so one that cannot be decrypted can still be forgotten.
  - `GET policy` answers `{"Blocklist":[...]}`, the only part of the policy that is enforced.
  - `POST policy/block` adds the `TKFSBlockEntry` in the body, its DN sanitized, replacing any entry with the same DN, NodeID and KekID. It answers 204, or 400 if the entry names none of them once the DN is sanitized.
  - `DELETE policy/block?dn=&nodeID=&kekID=` removes the entry whose DN, NodeID and KekID are exactly those, so removing `{DN}` leaves `{DN, NodeID}`. It answers 204, 400 if none is given, or 404 if no entry matches.
  - As on keep, the Blocklist changes one entry at a time under a lock, and there is no whole-policy write, so no admin writes back entries they did not name. The lock is per Nexus process, so simultaneous writes through two Nexus nodes can still lose one.

## Known gaps

- **The namespace is only soft-bound.** It is whatever the client sends, checked only for existence, so any system-subject cert can reach any namespace. A wrong or missing `gw.namespace` silently mints the KEK in that namespace, or in `default`.
- **Deleting the Nexus user revokes slowly.** It produces 401s, so the mount suspends only after three missed heartbeats. Removing the subject from `systemsubjects` produces 403 and suspends it at once.
- **Older Nexus builds** send `/tkfsdatakey/*` to the lizard proxy. Whatever comes back, the mount is refused before it serves.
