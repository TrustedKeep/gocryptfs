package tkc

import (
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"sync"

	"github.com/TrustedKeep/tkutils/v2/crypto"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

const dataFile = "/tmp/mockTKKeys"

type mockConnector struct {
	keys  map[string][]byte
	ready chan struct{}
	lock  sync.Mutex
}

var _ KMSConnector = &mockConnector{}

func newMockConnector() *mockConnector {
	tlog.Info.Printf("Using Mock TK connector")
	mc := &mockConnector{
		ready: make(chan struct{}),
		keys:  make(map[string][]byte),
	}
	data, err := ioutil.ReadFile(dataFile)
	if err == nil {
		tlog.Info.Printf("Loading keys from mock file")
		json.Unmarshal(data, &mc.keys)
		tlog.Info.Printf("Loaded %d keys from file", len(mc.keys))
	}
	return mc
}

func (m *mockConnector) Start() error {
	close(m.ready)
	return nil
}

func (m *mockConnector) Stop() {}

func (m *mockConnector) Ready() chan struct{} {
	return m.ready
}

func (m *mockConnector) GetKey(pathBytes []byte) (key []byte, err error) {
	m.lock.Lock()
	defer m.lock.Unlock()
	path := hex.EncodeToString(pathBytes)
	var found bool
	if key, found = m.keys[string(path)]; !found {
		key = crypto.NextKey()
		m.keys[string(path)] = key
		data, _ := json.Marshal(m.keys)
		if err = ioutil.WriteFile(dataFile, data, 0655); err != nil {
			return
		}
	}
	return
}
