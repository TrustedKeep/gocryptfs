package tkc

import (
	"bytes"
	"fmt"
	"sync"

	"github.com/TrustedKeep/tkutils/v2/kem"
	"github.com/google/uuid"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
	"go.etcd.io/bbolt"
)

var _ KMSConnector = &mockConnector{}

var (
	bucketName = []byte("b")
)

type mockConnector struct {
	nodeID string

	db *bbolt.DB
	mu sync.Mutex
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

func (m *mockConnector) GetEnvelopeKey(id string) (key kem.Kem, err error) {
	//get the key
	keyBytes, err := m.dbGet([]byte(m.ekPath(id)))
	if err != nil {
		return
	}
	//unmarshalKem
	return kem.UnmarshalKem(keyBytes)
}

func (m *mockConnector) CreateEnvelopeKey(ktStr string) (id string, key kem.Kem, err error) {
	//Create the key
	if key, err = kem.NewKem(kem.KemTypeFromString(ktStr)); err != nil {
		return
	}

	var keyData []byte
	if keyData, err = kem.MarshalKem(key); err != nil {
		return
	}
	//throw it into the db
	id = uuid.NewString()
	if err = m.dbPut([]byte(m.ekPath(id)), keyData); err != nil {
		return
	}

	return
}

func (m *mockConnector) dbGet(path []byte) (data []byte, err error) {
	err = m.db.View(func(t *bbolt.Tx) error {
		data = t.Bucket(bucketName).Get([]byte(path))
		return nil
	})
	return
}

func (m *mockConnector) dbPut(path []byte, value []byte) (err error) {
	err = m.db.Update(func(t *bbolt.Tx) error {
		return t.Bucket(bucketName).Put(path, value)
	})

	return
}

func (m *mockConnector) ekPath(id string) string {
	return fmt.Sprintf("%s/%s", m.nodeID, id)
}
