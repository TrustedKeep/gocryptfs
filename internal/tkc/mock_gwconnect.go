package tkc

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/TrustedKeep/tkutils/v2/kek"
	"github.com/google/uuid"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
	"go.etcd.io/bbolt"
)

var _ GatewayConnector = (*mockGatewayConnector)(nil)

// MockGatewayDBPath is the default bbolt store for the mock gateway's KEKs. -init and the
// mount run as separate processes, so the KEKs must outlive a single process for unwrap to
// succeed on the next mount.
const MockGatewayDBPath = "/tmp/tkfs_mock_gateway.db"

var mockGatewayBucket = []byte("kek")

// mockGatewayConnector emulates the gateway data-key API in-process with tkutils/kek. It
// holds the KEKs the real gateway would keep server-side — one per generated key ID —
// persisted in bbolt and scoped by keyspace so distinct filesystems can't unwrap each
// other's keys.
type mockGatewayConnector struct {
	keyspace string
	db       *bbolt.DB
}

func newMockGatewayConnector(nodeID, dbPath string) *mockGatewayConnector {
	if nodeID == "" {
		tlog.Fatal.Printf("mock gateway: empty NodeID would defeat keyspace isolation")
		os.Exit(exitcodes.Other)
	}
	if dbPath == "" {
		dbPath = MockGatewayDBPath
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
	return &mockGatewayConnector{
		keyspace: Keyspace("", nodeID),
		db:       db,
	}
}

// GenerateDataKey mints a fresh KEK, wraps a new master key under it, and persists the KEK
// so the ciphertext can be unwrapped later.
func (m *mockGatewayConnector) GenerateDataKey() (DataKey, error) {
	k, err := kek.Generate(kek.AES256_GCM)
	if err != nil {
		return DataKey{}, err
	}
	pt, ct, err := k.Wrap()
	if err != nil {
		return DataKey{}, err
	}
	keyID := uuid.NewString()
	if err = m.put(keyID, kek.Pack(k)); err != nil {
		return DataKey{}, err
	}
	return DataKey{KeyID: keyID, Plaintext: pt, Ciphertext: ct}, nil
}

// UnwrapDataKey looks up the KEK for keyID within this keyspace and unwraps the ciphertext.
func (m *mockGatewayConnector) UnwrapDataKey(keyID string, ciphertext []byte) ([]byte, error) {
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
		return nil, fmt.Errorf("unknown data key %q in keyspace %q", keyID, m.keyspace)
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

// storeKey namespaces a key ID under this keyspace. keyID is a UUID on write and validated
// to contain no "/" on read, so the trailing "/" unambiguously separates the two.
func (m *mockGatewayConnector) storeKey(keyID string) []byte {
	return []byte(m.keyspace + "/" + keyID)
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
