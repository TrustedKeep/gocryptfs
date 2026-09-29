package tkc

// TrustedGateway data-key API contract.
//
// keep holds the key-encryption key (KEK) and wraps/unwraps 32-byte AES-256 data keys; the gateway
// proxies. TKFS never holds the KEK and holds an unwrapped data key only long enough to HKDF-derive the
// filename and content keys, then zeroizes it (mount.go).
//
//	generate   POST .../tkfsdatakey/generate   -> {KeyID, Ciphertext, TransitWrappedKey}
//	unwrap     POST .../tkfsdatakey/unwrap     -> {TransitWrappedKey}
//	heartbeat  POST .../tkfsdatakey/heartbeat  -> {Command}
//
// The plaintext never crosses the wire even inside mTLS: each call sends an ephemeral transport public
// key and the response comes back wrapped to it (see gwconnect.go, newTransport). Only Ciphertext is
// persisted, in the key ring beside gocryptfs.conf. -init writes no ring, so the first mount generates
// and later mounts unwrap every retained entry, one round trip each.
//
// One KEK serves an instance for its whole life and its id is the instance's identity: the first
// generate goes out with no InstanceID, mints it, and the returned KeyID is what the ring records and
// the instance reports from then on. So every entry carries the same KeyID and only Ciphertext tells
// them apart, and the identity cannot name a KEK the ring does not use.
//
// A call succeeds when the signing CA is trusted, the cert DN is in the ACL, and no blocklist entry
// names the DN, NodeID or InstanceID; keep makes that decision. What it cannot check is which instance
// is calling, since the identity ships beside the Ciphertext on untrusted storage. The tenant is the
// hard boundary and per-instance separation a partition within it.

import (
	"errors"
	"fmt"
	"sync"

	"github.com/TrustedKeep/tkutils/v2/model"
)

// tkfsDataKeyLength is the size of the master key the gateway wraps: a 32-byte AES-256 key
// from which the EME (filename) and content keys are HKDF-derived.
const tkfsDataKeyLength = 32

// TKFSDataKey is the result of a generate operation.
type TKFSDataKey struct {
	// KeyID names the KEK this key was wrapped under — the instance's one KEK, so the same value on
	// every generate, and also the instance's identity. It is persisted in the ring and passed back on
	// unwrap so the gateway can select that KEK. It does not identify the ring entry; Ciphertext does.
	KeyID string
	// Plaintext is the 32-byte master key. Memory only — it is never written to disk.
	Plaintext []byte
	// Ciphertext is the wrapped master key. This is what the on-disk key ring stores.
	Ciphertext []byte
}

// instanceIdentity is a connector's TKFS identity: the id of the KEK that wraps this filesystem's data
// keys. It is empty on a cipherdir that has never mounted, and is established either by the generate
// that mints that KEK or by the key ring a later mount reads it back from. Guarded because the
// heartbeat goroutine reads it while a ctlsock-driven rotation can be inside generate.
type instanceIdentity struct {
	mu sync.RWMutex
	id string
}

func (i *instanceIdentity) get() string {
	i.mu.RLock()
	defer i.mu.RUnlock()
	return i.id
}

// adopt records an identity learned from a mint or from the key ring. Adopting the same id again is
// how a rotation looks; a different one means the key service answered under a KEK this filesystem
// does not use, which is an error rather than a silently kept first value.
func (i *instanceIdentity) adopt(id string) error {
	if id == "" {
		return nil
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.id == "" {
		i.id = id
		return nil
	}
	if i.id != id {
		return fmt.Errorf("this filesystem's identity is KEK %q, but %q was offered", i.id, id)
	}
	return nil
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
	// AdoptIdentity tells the connector this filesystem's identity, read back from its key ring.
	// The first mount of a cipherdir has none to give and learns it from the generate that mints
	// the KEK instead; every later mount, including one that adopted another mount's ring rather
	// than generating, has to hand it over here or its next generate would mint a second KEK.
	//
	// Idempotent. A non-empty id that contradicts one already held is an error.
	AdoptIdentity(id string) error
	// Close releases the connector's resources: network connections for the real
	// connectors, the bbolt handle for the mock. Called from the unmount teardown.
	Close() error
}

// Heartbeater is the liveness-and-registration half of the key-service contract. Both real connectors
// implement it; it is a separate interface from DataKeyConnector, asserted for at mount, because the
// mock has no route to beat to by design. The first unanswered heartbeat refuses the mount, which
// would otherwise make -mock-kms and the whole integration suite self-destruct.
type Heartbeater interface {
	// Heartbeat reports this instance as alive and says which key-ring index it is writing under.
	// That index is how a rotation becomes visible to an operator, and how a rekey the key service
	// asked for is seen to have been carried out.
	//
	// A returned ErrDenied means authorization is gone, not that the key service is unavailable,
	// and the caller must act on it immediately rather than retrying.
	Heartbeat(keyIdx uint16) (model.TKFSHeartbeatResponse, error)
}

// ErrDenied wraps every HTTP 403 from the gateway: the DN left the ACL, its CA was removed, or a
// blocklist entry names this instance. It is separated from every other failure because it is a
// decision rather than an outage — the caller must not spend a retry budget on it.
var ErrDenied = errors.New("the gateway refused this instance")

// ErrNotImplemented wraps an HTTP 404 or 501: the route does not exist on the key service this
// mount is talking to. It is separated from every other failure because it says nothing about this
// instance — a build that predates a route still serves the ones it has — so it is neither a refusal
// nor an outage.
var ErrNotImplemented = errors.New("the key service does not implement this route")
