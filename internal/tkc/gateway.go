package tkc

import "fmt"

// TrustedGateway data-key API contract (net-new gateway endpoints).
//
// The gateway (backed by keep) holds the key-encryption key (KEK) and wraps/unwraps
// 32-byte AES-256 data keys under it. TKFS never holds the KEK and never persists any
// plaintext key; it holds an unwrapped data key — and the EME/content keys HKDF-derived
// from it — in memory only, for the life of the mount, zeroized on unmount. The operations
// map to gateway HTTP routes reached over mutually-authenticated TLS:
//
//	generate  POST .../tkfsdatakey/generate  -> {KeyID, Ciphertext} (+ Plaintext in the mTLS body)
//	unwrap    POST .../tkfsdatakey/unwrap    -> {Plaintext}
//
// Only Ciphertext is persisted, in the gocryptfs.conf key ring. Rotation is not a distinct
// operation: it is just another generate whose result is appended to the key ring as the
// new active key, with prior entries retained for unwrap.
//
// Authorization is per-operation: the gateway matches the client cert DN against a
// {generate,unwrap} allowlist. Key isolation between filesystems is by
// keyspace = DN + NodeID (see Keyspace) — the DN comes from the client cert on the real
// connector, the NodeID travels in the request. The mock connector has no cert, so it
// passes an empty DN.

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
	// Ciphertext is the wrapped master key. This is what the config key ring stores.
	Ciphertext []byte
}

// GatewayConnector is the client side of the gateway data-key API. It supersedes the
// envelope-model KMSConnector for the KEK wrapped-key design; the two coexist
// until the envelope path is removed in a later phase.
type GatewayConnector interface {
	// GenerateTKFSDataKey mints a fresh data key wrapped by the gateway KEK. Rotation is
	// performed by calling this again and appending the result to the key ring.
	GenerateTKFSDataKey() (TKFSDataKey, error)
	// UnwrapTKFSDataKey recovers the plaintext master key for a key-ring entry.
	UnwrapTKFSDataKey(keyID string, ciphertext []byte) (plaintext []byte, err error)
	// Close releases the connector's resources: network connections for the real
	// connector, the bbolt handle for the mock. Not yet wired into the unmount path —
	// the gateway connector joins the mount/crypto lifecycle in a later phase.
	Close() error
}

// Keyspace returns the per-filesystem key-isolation scope for a (DN, NodeID) pair. Each
// component is length-prefixed so the composition is injective even when a component itself
// contains the "/" delimiter (a DN may): distinct pairs never collide. The DN comes from
// the client cert on the real connector; the mock passes an empty DN.
func Keyspace(dn, nodeID string) string {
	return fmt.Sprintf("%d:%s/%d:%s", len(dn), dn, len(nodeID), nodeID)
}
