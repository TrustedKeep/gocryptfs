package tkc

// TrustedGateway data-key API contract (net-new gateway endpoints).
//
// The gateway (backed by keep) holds the key-encryption key (KEK) and wraps/unwraps
// 32-byte AES-256 data keys under it. TKFS never holds the KEK and never persists any
// plaintext key; it holds an unwrapped data key — and the EME/content keys HKDF-derived
// from it — in memory only, for the life of the mount, zeroized on unmount. The operations
// map to gateway HTTP routes reached over mutually-authenticated TLS:
//
//	generate  POST .../datakey/generate  -> {KeyID, Ciphertext} (+ Plaintext in the mTLS body)
//	unwrap    POST .../datakey/unwrap    -> {Plaintext}
//
// Only Ciphertext is persisted, in the gocryptfs.conf key ring. Rotation is not a distinct
// operation: it is just another generate whose result is appended to the key ring as the
// new active key, with prior entries retained for unwrap.
//
// Authorization is per-operation: the gateway matches the client cert DN against a
// {generate,unwrap} allowlist. Key isolation between filesystems is by
// keyspace = DN + NodeID — the DN comes from the client cert on the real connector, the
// NodeID travels in the request. The mock connector has no cert, so its keyspace is the
// NodeID alone.

// dataKeyLength is the size of the master key the gateway wraps: a 32-byte AES-256 key
// from which the EME (filename) and content keys are HKDF-derived.
const dataKeyLength = 32

// DataKey is the result of a generate operation.
type DataKey struct {
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
	// GenerateDataKey mints a fresh data key wrapped by the gateway KEK. Rotation is
	// performed by calling this again and appending the result to the key ring.
	GenerateDataKey() (DataKey, error)
	// UnwrapDataKey recovers the plaintext master key for a key-ring entry.
	UnwrapDataKey(keyID string, ciphertext []byte) (plaintext []byte, err error)
}

// Keyspace returns the per-filesystem key-isolation scope, keyspace = DN + NodeID. On the
// mock connector dn is empty, so the keyspace is the NodeID alone.
func Keyspace(dn, nodeID string) string {
	if dn == "" {
		return nodeID
	}
	return dn + "/" + nodeID
}
