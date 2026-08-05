# Phase 1.5 — Transit-wrap the data key + active key-memory hygiene

Status: draft / design. Builds on the phase-1 gateway mTLS connector
(`internal/tkc/gwconnect.go`, `gateway.go`, `mock_gwconnect.go`).

## Goal

Two hardenings to the gateway data-key path, both narrowing how much the plaintext
data key (DEK) is exposed:

1. **Never put the plaintext DEK on the wire**, even inside mTLS. The gateway wraps
   the returned key to a client-held ephemeral key, so a compromised or inspected TLS
   channel (terminating proxy, mis-issued server cert, TLS bug, memory scrape at the
   TLS layer) yields nothing usable on its own.
2. **Deterministically evict and zeroize key material in RAM** — wipe on unmount, bound
   lifetime, and prevent swap — instead of relying on the lazy/async behavior of the
   generic LRU cache.

Algorithm decision (settled): **RSA-OAEP now.** The wire format carries a
`TransportAlg` identifier so a post-quantum KEM (`kem.Kyber768X25519`) can replace RSA
later with no protocol break and, per the reuse notes below, no client-code change.

---

## Reuse notes (answers to "do we have to write this ourselves?")

Both hardenings reuse existing, vetted tkutils code. Almost nothing here is net-new
crypto or a new cache.

### Q1 — Is there a cache we can reuse instead of writing one? Yes: `tkutils/lru`.

- `tkutils/lru` is **already used** by `internal/cryptocore/tk_aead_keys.go` for the key
  caches, and it **already runs an active background reaper** (`runExpire`) that fires a
  zeroizing eviction callback. So "actively remove from memory" is largely already
  present — the reaper deletes idle entries on a timer and invokes the callback.
- `tkutils/cache` is **not** the right tool: it is a distributed/external cache
  (redis / redis-cluster / memcached / memory) that encrypts values for storage in an
  external store, and its in-memory backend does not even implement expiry
  (`store_memory.go`: "expire not supported"). Wrong direction for holding plaintext
  key bytes in-process.
- There is **no ready-made secure-buffer / `Secret` type** in tkutils. The wipe
  primitive is `crypto.Zeroize([]byte)` (already used by cryptocore's callback), and
  `security.Memlock()` (Linux `mlockall(MCL_CURRENT|MCL_FUTURE)`) is a ready-made way to
  keep key pages out of swap.

So Part 2 does **not** introduce a custom keystore. It keeps `lru` and only changes how
we *use* it (see the two real gaps below), plus adds `security.Memlock()`.

The two gaps in `lru`, and how we close them without modifying `lru`:

| Gap in `lru` | Consequence | Fix (usage-level) |
| --- | --- | --- |
| `Purge()` / `Destory()` skip the eviction callback | unmount leaves key bytes for the GC, unwiped | on teardown, iterate `Keys()` and call `Remove(k)` for each — `Remove` fires the zeroize callback |
| TTL is **idle-based** (`lastAccess`, reset on every `Get`) | a hot key never expires and stays resident | acceptable as an idle timeout; if an **absolute** from-load lifetime is required, wrap the value with an `expiresAt` and drop it in the callback — a thin wrapper, not a rewrite |

(The callback runs as `go c.cb(...)` — async. That is fine for the idle-reaper path; for
the deterministic unmount wipe we call `Remove` per key so the wipe is driven by us.)

### Q2 — Do we already have pub/private-key + OAEP code? Yes: `kem` + `certutil`.

- **Client transport keypair — no new key code.** `kem.NewKem(kem.RSA3072)` generates the
  RSA keypair, `GetPublicKey()` exposes the public key, and `Unwrap()` is exactly
  `rsa.DecryptOAEP(sha256, priv, wrapper)` — it decrypts *any* OAEP ciphertext, not only
  kem-minted ones (confirmed in `kem/rsa.go`). So the client creates a `kem.Kem`, sends
  its public key, and calls `Unwrap` on the response.
- **Public-key marshal/parse:** `certutil.EncodePublicKey(any)` (PEM; PKCS1 for RSA, PKIX
  otherwise) and `certutil.ParsePublicKey([]byte)`. `certutil.GeneratePrivateKey(
  certutil.KeyTypeRSA)` also generates an RSA-3072 key if we prefer the raw route.
- **The only op with no helper** is OAEP-*encrypting* an already-existing DEK on the
  gateway side — a single `rsa.EncryptOAEP(...)` call, which is exactly the pattern
  already in `internal/tkc/tbconnect.go` (`GetKey`).
- **PQ path is a one-line swap later:** `certutil.KeyTypeKyber == kem.Kyber768X25519`, and
  `kem.Unwrap` already handles Kyber, so moving the transport to PQ is a `TransportAlg`
  change on the gateway plus selecting a different `kem.KemType` on the client.

---

## Part 1 — Client-ephemeral transit wrap

### Threat closed

Today `UnwrapTKFSDataKey` / `GenerateTKFSDataKey` return the 32-byte DEK as a plaintext
field (`gateway.go` `TKFSDataKey.Plaintext`, `gwconnect.go` `unwrapResponse.Plaintext`)
protected only by TLS. We add a second, end-to-end layer that the transport cannot see
through: the gateway encrypts the DEK to a fresh public key that only the requesting
process holds the private half of.

Ephemeral **per request** (not per mount): `generate` (init/rotate) and `unwrap` (mount)
are infrequent, so a fresh keypair per call is affordable and gives the transit wrap
forward secrecy.

### Wire protocol change (coordinated with tkutils `model` — TK-1391)

> **Superseded name (Phase 2):** the response field this section calls `WrappedKey` was renamed to
> **`TransitWrappedKey`** during Phase 2, because it collided with keep/oec's `KekWrapResponse.WrappedKey`
> — which is the durable *KEK ciphertext*, not the per-call transit-wrapped plaintext. Both are `[]byte`,
> so the two were interchangeable to the compiler. Read every `WrappedKey` below as `TransitWrappedKey`;
> the rest of the design is unchanged. See `Documentation/phase-2-kek-lifecycle.md`.

These wire types mirror `model.TKFSDataKey{Generate,Unwrap}{Request,Response}` (see the
comment block in `gwconnect.go`), so the field changes must land in tkutils `model` too.
`Plaintext` is replaced by `WrappedKey`; the request gains the transport key.

```go
type generateRequest struct {
	NodeID          string
	TransportAlg    uint16 // kem.KemType of the ephemeral transport key
	TransportPubKey []byte // PEM-encoded ephemeral public key
}

type generateResponse struct {
	KeyID      string
	Ciphertext []byte // KEK-wrapped master key (persisted) — unchanged
	WrappedKey []byte // DEK wrapped to TransportPubKey (replaces Plaintext)
}

type unwrapRequest struct {
	NodeID          string
	KeyID           string
	Ciphertext      []byte
	TransportAlg    uint16
	TransportPubKey []byte
}

type unwrapResponse struct {
	WrappedKey []byte // replaces Plaintext
}
```

`TKFSDataKey.Plaintext` stays as the in-memory return of the connector methods; it just
never crosses the wire — it is recovered locally by unwrapping `WrappedKey`.

### Client side (real connector) — reuses `kem` + `certutil`

```go
// newTransport creates a per-call ephemeral wrap keypair. kem.NewKem gives RSA keygen +
// OAEP unwrap for free; a later switch of TransportAlg to kem.Kyber768X25519 needs no
// change here (kem.Unwrap handles it).
func newTransport() (k kem.Kem, pubPEM []byte, err error) {
	if k, err = kem.NewKem(kem.RSA3072); err != nil {
		return
	}
	pubPEM, err = certutil.EncodePublicKey(k.GetPublicKey())
	return
}
```

```go
func (g *gwConnector) UnwrapTKFSDataKey(keyID string, ciphertext []byte) ([]byte, error) {
	if keyID == "" {
		return nil, fmt.Errorf("gateway unwrap: empty key id")
	}
	k, pubPEM, err := newTransport()
	if err != nil {
		return nil, fmt.Errorf("gateway unwrap: transport keygen: %w", err)
	}
	req := unwrapRequest{
		NodeID: g.nodeID, KeyID: keyID, Ciphertext: ciphertext,
		TransportAlg: uint16(kem.RSA3072), TransportPubKey: pubPEM,
	}
	var out unwrapResponse
	if err := g.post(gatewayUnwrapPath, req, &out); err != nil {
		return nil, err
	}
	dek, err := k.Unwrap(out.WrappedKey) // rsa.DecryptOAEP under the hood
	if err != nil {
		return nil, fmt.Errorf("gateway unwrap: transport unwrap: %w", err)
	}
	if len(dek) != tkfsDataKeyLength {
		return nil, fmt.Errorf("gateway unwrap: expected %d-byte data key, got %d", tkfsDataKeyLength, len(dek))
	}
	return dek, nil
}
```

`GenerateTKFSDataKey` changes the same way: build a transport, send it, and
`k.Unwrap(out.WrappedKey)` in place of reading `out.Plaintext`. A response carrying a
plaintext field / `TransportAlg == 0` is rejected once the gateway supports wrapping, so
we can never silently fall back to plaintext-on-wire in production.

### Gateway side (keep / TK-1391) — spec, and the mock implements it

The gateway wraps the DEK to the client's transport key. The **tkfs mock**
(`internal/tkc/mock_gwconnect.go`) implements the identical wrap so the whole path is
exercised by tkfs tests today — no dependency on the real gateway being built.

```go
// shared by the real gateway and the mock
func wrapForTransport(alg uint16, pubPEM, dek []byte) ([]byte, error) {
	switch kem.KemType(alg) {
	case kem.RSA2048, kem.RSA3072, kem.RSA4096:
		pub, err := certutil.ParsePublicKey(pubPEM)
		if err != nil {
			return nil, fmt.Errorf("parse transport key: %w", err)
		}
		rp, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("transport key is not RSA")
		}
		return rsa.EncryptOAEP(sha256.New(), rand.Reader, rp, dek, nil)
	default:
		return nil, fmt.Errorf("unsupported transport alg %d", alg)
	}
}
```

In the mock's `GenerateTKFSDataKey`, the freshly minted plaintext (`pt`) is passed through
`wrapForTransport` into `WrappedKey` and is **not** returned in the clear. (Optional
tidy-up for the generate path only: `kem.WrapFor(clientPub)` mints *and* OAEP-wraps a
fresh 32-byte key in one call — but it cannot wrap an already-existing key, so `unwrap`
still needs the explicit `rsa.EncryptOAEP` above; keep both paths on the one helper for
uniformity.)

---

## Part 2 — Active, deterministic key-memory hygiene

No new cache. Keep `tkutils/lru` (already used by cryptocore) with its zeroizing
eviction callback, and close the two usage-level gaps plus add swap protection.

### 2a. Wipe on teardown (the real bug today)

> **Superseded (Phase 2):** this section is moot — the caches it wipes no longer exist. Phase 2
> ripped the envelope model, which took `tk_aead_keys.go`'s two LRU caches with it, and the
> `WipeCache` helper this describes shipped as `internal/cryptocore/wipe.go`, sat unwired, and was
> deleted in the 2026-08-04 review round as the last `tkutils/lru` user. The KEK model has no key
> cache to purge: the master key is zeroized immediately after `cryptocore.New`, so nothing is
> resident at unmount but the ciphers themselves. What remains open is narrower — making
> `CryptoCore.Wipe()` zeroize the *derived* EME/content key bytes rather than only nilling the
> stdlib cipher refs. See `Documentation/phase-2-kek-lifecycle.md` §5.

`lru.Purge()` / `Destory()` do not invoke the eviction callback, so a mount that tears
down its caches leaves key bytes unwiped for the GC. Replace any such teardown with a
per-key `Remove`, which fires the zeroize callback:

```go
// wipe deterministically clears a key cache: Remove fires the zeroize callback;
// Purge/Destory do not.
func wipe(c *lru.Cache) {
	for _, k := range c.Keys() {
		c.Remove(k)
	}
}
```

Call `wipe(keys)` / `wipe(decryptedCache)` on unmount.

### 2b. Wipe the gateway master key on unmount

In the KEK model the unwrapped master key is deliberately resident for the life of the
mount (everything HKDF-derives from it). Make its removal deterministic: hold it as a
`[]byte` owned by the connector and zeroize it in `gwConnector.Close()` (already called
on unmount):

```go
func (g *gwConnector) Close() error {
	g.stopOnce.Do(func() { close(g.stop) })
	if client := g.currentClient(); client != nil {
		client.CloseIdleConnections()
	}
	cryptoutil.Zeroize(g.masterKey) // deterministic wipe, not left to GC
	return nil
}
```

### 2c. Keep keys out of swap

Call `security.Memlock()` once at mount startup (Linux `mlockall(MCL_CURRENT|MCL_FUTURE)`;
a no-op on Darwin). This prevents the resident master key (and everything else) from
being paged to disk, which is a stronger guarantee for the mount-lifetime master key than
any eviction policy.

### Honest scoping note

Because the master key must persist for the mount's life, actively evicting *derived*
keys while the master stays resident has limited security value — an attacker scraping
live RAM gets the master regardless. The real wins in Part 2 are therefore:

1. **Deterministic wipe on unmount** (2a, 2b) — fixes the current "leave it to the GC" gap.
2. **No swap** (2c) — the master key never lands on disk.
3. **Bounded lifetime for transient plaintext and (later) derived keys** via the existing
   idle reaper.

When the KEK model is wired into `cryptocore` (a later phase), back the derived
EME/content-key cache with the same `lru` + zeroize callback and the `wipe`-on-unmount
discipline; adopt an absolute-TTL wrapper only if a hard cap on derived-key residency is
required.

---

## Test plan (all in-tkfs, no real gateway needed)

- **Transit round-trip:** mock gateway wraps to the client's `TransportPubKey`; the
  connector recovers the exact DEK via `kem.Unwrap`. A wrong/absent transport key fails
  closed.
- **No-plaintext invariant:** assert the DEK bytes never appear in the marshaled
  request/response bodies; a `TransportAlg == 0` / plaintext response is rejected.
- **Unsupported alg:** `wrapForTransport` errors on an unknown `TransportAlg`.
- **Zeroize on evict:** install the callback, force eviction, assert the backing slice is
  zeroed.
- **Wipe on teardown:** `wipe(cache)` zeroizes every entry (assert bytes are zero) and the
  cache is empty afterward.
- **Master-key wipe:** after `gwConnector.Close()`, the master-key slice is zeroed.
- `go test -race` for the reaper/close paths (no goroutine leak, no data race).

## Sequencing & dependencies

1. **tkfs-only, landable now:** wire-type change, client transport (`kem`/`certutil`),
   mock `wrapForTransport`, `wipe` on teardown, `Close()` master-key zeroize,
   `security.Memlock()` at startup, tests.
2. **Cross-repo (TK-1391):** mirror the request/response field changes in tkutils `model`;
   implement `wrapForTransport` in keep's gateway. Until it lands, gate a plaintext mode
   behind a dev-only flag for the mock path; production requires `WrappedKey`.
3. **Depends on the KEK-in-cryptocore phase:** applying the `lru` + `wipe` discipline to
   the derived-key cache.

## Open items

- Whether to make the transport key **per request** (drafted; forward-secret, keygen cost
  negligible at mount/rotate frequency) or per mount (cheaper). Recommendation: per
  request.
- Whether derived keys need an **absolute** TTL cap (thin `lru` value wrapper) or the
  idle timeout suffices. Recommendation: idle timeout unless a compliance cap is required.
