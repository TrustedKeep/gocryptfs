package tkc

// TrustedGateway data-key API contract (net-new gateway endpoints).
//
// keep holds the key-encryption key (KEK) and performs the wrap/unwrap of 32-byte AES-256 data keys;
// the gateway is a proxy that forwards those calls (see gatehouse management/tkfsdatakey.go). TKFS
// never holds the KEK and never persists any plaintext key. It holds an unwrapped data key only long
// enough to HKDF-derive the EME (filename) and content keys, then zeroizes it immediately (mount.go);
// those derived keys live in memory for the mount and are wiped on unmount. The operations map to
// gateway HTTP routes reached over mutually-authenticated TLS:
//
//	generate  POST .../tkfsdatakey/generate  -> {KeyID, Ciphertext, TransitWrappedKey}
//	unwrap    POST .../tkfsdatakey/unwrap    -> {TransitWrappedKey}
//
// The plaintext data key never crosses the wire even inside mTLS: the client sends a per-call
// ephemeral transport public key and the gateway returns the key OAEP-wrapped to it
// (TransitWrappedKey), which the client unwraps in memory (see gwconnect.go, newTransport).
// Of the key material, only Ciphertext is persisted, in the key-ring file next to gocryptfs.conf
// (alongside the non-secret KeyID; the NodeID lives in the config). -init does not contact the
// gateway and writes no ring: the first mount finds none, generates the data key, and persists its
// ciphertext; later mounts unwrap it. Phase 2 is single-key: at most one ring entry is accepted and
// a ring with more fails the mount closed.
// Rotation — another generate appended as the new active key, with prior entries retained for
// unwrap — is Phase 3 and is NOT implemented here yet.
//
// Authorization is per-operation: the gateway matches the client cert DN against a {generate,unwrap}
// allowlist. Key isolation is by keyspace = DN + NodeID, composed entirely server-side (the gateway
// takes the DN from the presented cert; the NodeID travels in the request body), so the client never
// composes a keyspace itself — the one definition of that composition is model.TKFSKeyspace in
// tkutils, which the gateway calls. Note only the cert-derived DN half is unforgeable: NodeID is
// self-asserted and ships next to the KeyID and Ciphertext, so treat the DN/tenant as the hard
// boundary and NodeID as a partition within it.

// tkfsDataKeyLength is the size of the master key the gateway wraps: a 32-byte AES-256 key
// from which the EME (filename) and content keys are HKDF-derived.
const tkfsDataKeyLength = 32

// TKFSDataKey is the result of a generate operation.
type TKFSDataKey struct {
	// KeyID identifies the wrapping-key generation. It is persisted in the ring and
	// passed back on unwrap so the gateway can select the right KEK.
	KeyID string
	// Plaintext is the 32-byte master key. Memory only — it is never written to disk.
	Plaintext []byte
	// Ciphertext is the wrapped master key. This is what the on-disk key ring stores.
	Ciphertext []byte
}

// DataKeyConnector is the client side of the KEK data-key API. Both the default gateway
// connector (mTLS to TrustedGateway) and the -search connector (mTLS + tenant token to the
// TrustedSearch KMS) implement it; they differ only in endpoint, auth, and cert source. It is
// the sole key provider in the KEK model, replacing the envelope-model KMS connector.
type DataKeyConnector interface {
	// GenerateTKFSDataKey mints a fresh data key wrapped by the gateway KEK. Rotation is
	// performed by calling this again and appending the result to the key ring.
	GenerateTKFSDataKey() (TKFSDataKey, error)
	// UnwrapTKFSDataKey recovers the plaintext master key for a key-ring entry.
	UnwrapTKFSDataKey(keyID string, ciphertext []byte) (plaintext []byte, err error)
	// Close releases the connector's resources: network connections for the real
	// connectors, the bbolt handle for the mock. Called from the unmount teardown.
	Close() error
}
