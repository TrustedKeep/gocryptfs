package tkc

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/TrustedKeep/tkutils/v2/kek"
	"github.com/google/uuid"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
	"go.etcd.io/bbolt"
)

var _ DataKeyConnector = (*mockGatewayConnector)(nil)

// mockGatewayDBPath derives a per-NodeID bbolt store path under the temp dir. Each mount is a
// separate process, so the KEKs must outlive a single process; keying the store by NodeID
// (which is stable and persisted in the config) keeps a filesystem's first mount (generate) and
// later mounts (unwrap) on the same store, while letting independent filesystems — e.g. parallel
// integration tests — each use their own store instead of contending on one bbolt file lock.
func mockGatewayDBPath(nodeID string) string {
	safe := strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		default:
			return '_'
		}
	}, nodeID)
	return filepath.Join(os.TempDir(), "tkfs_mock_gateway_"+safe+".db")
}

var mockGatewayBucket = []byte("kek")

// mockGatewayConnector emulates the gateway data-key API in-process with tkutils/kek. It holds the
// KEKs the real gateway would keep server-side — one per generated key ID — persisted in bbolt and
// keyed by key ID. Unwrap selects the KEK by key ID alone. That is a mock simplification, NOT a mirror
// of the server: keep's TKFS unwrap goes through KekUnwrapScoped, which additionally requires the key
// ID to be the KEK the caller's keyspace currently owns. So mock-backed tests cannot catch a
// keyspace-scoping regression — that behavior is covered by keep's own tests.
type mockGatewayConnector struct {
	db *bbolt.DB
}

func newMockGatewayConnector(nodeID, dbPath string) *mockGatewayConnector {
	if nodeID == "" {
		tlog.Fatal.Printf("mock gateway: empty NodeID (it names this filesystem's key store)")
		os.Exit(exitcodes.Other)
	}
	if dbPath == "" {
		dbPath = mockGatewayDBPath(nodeID)
	}
	// Timeout so a stale lock fails fast instead of hanging a mount forever.
	db, err := bbolt.Open(dbPath, 0600, &bbolt.Options{Timeout: time.Second})
	if err != nil {
		tlog.Fatal.Printf("Error opening mock gateway store: %v", err)
		os.Exit(exitcodes.Other)
	}
	if err = db.Update(func(t *bbolt.Tx) error {
		_, err := t.CreateBucketIfNotExists(mockGatewayBucket)
		return err
	}); err != nil {
		tlog.Fatal.Printf("Error creating mock gateway bucket: %v", err)
		os.Exit(exitcodes.Other)
	}
	return &mockGatewayConnector{db: db}
}

// GenerateTKFSDataKey mints a fresh KEK, wraps a new master key under it, and persists the KEK
// so the ciphertext can be unwrapped later.
func (m *mockGatewayConnector) GenerateTKFSDataKey() (TKFSDataKey, error) {
	k, err := kek.Generate(kek.AES256_GCM)
	if err != nil {
		return TKFSDataKey{}, err
	}
	pt, ct, err := k.Wrap()
	if err != nil {
		return TKFSDataKey{}, err
	}
	keyID := uuid.NewString()
	if err = m.put(keyID, kek.Pack(k)); err != nil {
		return TKFSDataKey{}, err
	}
	return TKFSDataKey{KeyID: keyID, Plaintext: pt, Ciphertext: ct}, nil
}

// UnwrapTKFSDataKey looks up the KEK for keyID within this keyspace and unwraps the ciphertext.
func (m *mockGatewayConnector) UnwrapTKFSDataKey(keyID string, ciphertext []byte) ([]byte, error) {
	// keyID comes from the persisted key ring; reject values that would make the storeKey
	// composition ambiguous before they reach the store.
	if keyID == "" || strings.Contains(keyID, "/") {
		return nil, fmt.Errorf("invalid data key id %q", keyID)
	}
	packed, err := m.get(keyID)
	if err != nil {
		return nil, err
	}
	if len(packed) == 0 {
		return nil, fmt.Errorf("unknown data key %q", keyID)
	}
	k, err := kek.Unpack(packed)
	if err != nil {
		return nil, err
	}
	return k.Unwrap(ciphertext)
}

// Close releases the bbolt file lock.
func (m *mockGatewayConnector) Close() error {
	return m.db.Close()
}

// storeKey is the bbolt key for a KEK: the key ID itself. Unwrap looks up by key ID alone, so no
// keyspace prefix is applied (see the type doc — the real server also gates on the keyspace).
func (m *mockGatewayConnector) storeKey(keyID string) []byte {
	return []byte(keyID)
}

func (m *mockGatewayConnector) put(keyID string, packed []byte) error {
	return m.db.Update(func(t *bbolt.Tx) error {
		return t.Bucket(mockGatewayBucket).Put(m.storeKey(keyID), packed)
	})
}

func (m *mockGatewayConnector) get(keyID string) (packed []byte, err error) {
	err = m.db.View(func(t *bbolt.Tx) error {
		// bbolt values are only valid inside the transaction, so copy it out.
		if v := t.Bucket(mockGatewayBucket).Get(m.storeKey(keyID)); v != nil {
			packed = make([]byte, len(v))
			copy(packed, v)
		}
		return nil
	})
	return
}
