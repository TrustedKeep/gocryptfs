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

// mockGatewayOpenTimeout bounds the wait for a peer mount's bbolt file lock.
const mockGatewayOpenTimeout = 30 * time.Second

// mockKeyEpoch starts the mock's key stamps far from any real clock, so a test can tell the key
// service's stamp from this host's.
var mockKeyEpoch = time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)

// mockGatewayConnector emulates the gateway data-key API in-process with tkutils/kek, keeping the KEKs
// keep would hold in bbolt. As in keep, a generate without an identity mints a KEK and one with an
// identity wraps under that KEK; unwrap selects the KEK by key ID alone.
type mockGatewayConnector struct {
	// dbPath is opened per operation, so every mount of a filesystem can share the store.
	dbPath   string
	identity instanceIdentity
}

func newMockGatewayConnector(nodeID, dbPath string) *mockGatewayConnector {
	if nodeID == "" {
		tlog.Fatal.Printf("mock gateway: empty NodeID (it names this filesystem's key store)")
		os.Exit(exitcodes.Other)
	}
	if dbPath == "" {
		dbPath = mockGatewayDBPath(nodeID)
	}
	m := &mockGatewayConnector{dbPath: dbPath}
	if err := m.withStore(true, func(*bbolt.Bucket) error { return nil }); err != nil {
		tlog.Fatal.Printf("Error opening mock gateway store: %v", err)
		os.Exit(exitcodes.Other)
	}
	return m
}

// GenerateTKFSDataKey wraps a new master key under the KEK the connector's identity names, minting
// that KEK when there is no identity yet.
func (m *mockGatewayConnector) GenerateTKFSDataKey() (TKFSDataKey, error) {
	var dk TKFSDataKey
	keyID := m.identity.get()
	err := m.withStore(true, func(b *bbolt.Bucket) error {
		var k kek.Kek
		var err error
		if keyID != "" {
			packed := b.Get(m.storeKey(keyID))
			if packed == nil {
				return fmt.Errorf("mock gateway: unknown KEK %q", keyID)
			}
			if k, err = kek.Unpack(packed); err != nil {
				return fmt.Errorf("mock gateway: unpacking KEK %q: %w", keyID, err)
			}
		} else {
			if k, err = kek.Generate(kek.AES256_GCM); err != nil {
				return err
			}
			keyID = uuid.NewString()
			if err = b.Put(m.storeKey(keyID), kek.Pack(k)); err != nil {
				return err
			}
		}
		// Inside the transaction: an unpacked KEK's key can point into the bbolt mmap, which is
		// only valid while the transaction is open. Wrap's outputs are freshly allocated.
		pt, ct, err := k.Wrap()
		if err != nil {
			return err
		}
		// The bucket's sequence counts generates by every process sharing the store.
		seq, err := b.NextSequence()
		if err != nil {
			return err
		}
		dk = TKFSDataKey{KeyID: keyID, Plaintext: pt, Ciphertext: ct,
			CreatedAt: mockKeyEpoch.Add(time.Duration(seq) * time.Second)}
		return nil
	})
	if err != nil {
		return TKFSDataKey{}, err
	}
	if err := m.identity.check(dk.KeyID); err != nil {
		return TKFSDataKey{}, fmt.Errorf("mock gateway generate: %w", err)
	}
	return dk, nil
}

// UnwrapTKFSDataKey looks up the KEK for keyID and unwraps the ciphertext.
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

// AdoptIdentity records the identity read out of this filesystem's key ring.
func (m *mockGatewayConnector) AdoptIdentity(id string) error {
	return m.identity.adopt(id)
}

// Close has nothing to release: every operation opens and closes the store itself.
func (m *mockGatewayConnector) Close() error {
	return nil
}

// storeKey is the bbolt key for a KEK: its key ID.
func (m *mockGatewayConnector) storeKey(keyID string) []byte {
	return []byte(keyID)
}

func (m *mockGatewayConnector) get(keyID string) (packed []byte, err error) {
	err = m.withStore(false, func(b *bbolt.Bucket) error {
		// bbolt values are only valid inside the transaction, so copy it out.
		if v := b.Get(m.storeKey(keyID)); v != nil {
			packed = make([]byte, len(v))
			copy(packed, v)
		}
		return nil
	})
	return
}

// withStore opens the store, runs fn on the KEK bucket in one transaction, and closes the store, so
// the bbolt file lock is held only for that transaction.
func (m *mockGatewayConnector) withStore(write bool, fn func(*bbolt.Bucket) error) (err error) {
	db, err := bbolt.Open(m.dbPath, 0600, &bbolt.Options{Timeout: mockGatewayOpenTimeout, ReadOnly: !write})
	if err != nil {
		return fmt.Errorf("mock gateway: opening store %s: %w", m.dbPath, err)
	}
	defer func() {
		if cerr := db.Close(); err == nil {
			err = cerr
		}
	}()
	if !write {
		return db.View(func(t *bbolt.Tx) error {
			b := t.Bucket(mockGatewayBucket)
			if b == nil {
				return fmt.Errorf("mock gateway: store %s has no KEK bucket", m.dbPath)
			}
			return fn(b)
		})
	}
	return db.Update(func(t *bbolt.Tx) error {
		b, err := t.CreateBucketIfNotExists(mockGatewayBucket)
		if err != nil {
			return err
		}
		return fn(b)
	})
}
