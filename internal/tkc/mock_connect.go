package tkc

import (
	"bytes"
	"sync"

	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
	"go.etcd.io/bbolt"
)

var _ KMSConnector = &mockConnector{}

var (
	bucketName = []byte("b")
)

type mockConnector struct {
	nodeID string
	db     *bbolt.DB
	mu     sync.Mutex
}

func newMockConnector(nodeID string) *mockConnector {
	db, err := bbolt.Open("/tmp/tkfs_mock_keys.db", 0600, &bbolt.Options{})
	if err != nil {
		tlog.Fatal.Printf("Error opening mock key file: %v", err)
	}
	if err = db.Update(func(t *bbolt.Tx) error {
		_, err := t.CreateBucketIfNotExists(bucketName)
		return err
	}); err != nil {
		tlog.Fatal.Printf("Error creating default bucket: %v", err)
	}
	return &mockConnector{
		nodeID: nodeID,
		db:     db,
	}
}

func (m *mockConnector) GetKey(path []byte) (key []byte, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()

	fullPath := bytes.Join([][]byte{[]byte(m.nodeID), path}, []byte("/"))
	m.db.View(func(t *bbolt.Tx) error {
		key = t.Bucket(bucketName).Get(fullPath)
		return nil
	})
	if len(key) == 0 {
		key = make([]byte, 32)
		if err = m.db.Update(func(t *bbolt.Tx) error {
			return t.Bucket(bucketName).Put(fullPath, key)
		}); err == nil {
			tlog.Info.Printf("Created new TKFS key %s", string(fullPath))
		}
	}
	return
}
