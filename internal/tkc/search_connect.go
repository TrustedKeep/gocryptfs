package tkc

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"github.com/TrustedKeep/tkutils/v2/kem"
)

var errNotImplemented = errors.New("not implemented in search connector")

var _ KMSConnector = (*searchConnector)(nil)

type searchConnector struct {
	currKeyID string
	client    *http.Client
}

func newSearchConnector() KMSConnector {
	return &searchConnector{
		client: &http.Client{
			Timeout: time.Second * 2,
			Transport: &http.Transport{
				MaxIdleConns:    1,
				MaxConnsPerHost: 2,
				IdleConnTimeout: time.Minute,
			},
		},
	}
}

func (sc *searchConnector) GetKey(path []byte) ([]byte, error) {
	return nil, errNotImplemented
}

func (sc *searchConnector) GetEnvelopeKey(id string) (key kem.Kem, err error) {
	_, key, err = sc.fetchKey(id)
	return
}

func (sc *searchConnector) CreateEnvelopeKey(ktStr string, name string) (id string, key kem.Kem, err error) {
	return sc.fetchKey("")
}

func (sc *searchConnector) GetCurrentKeyID() string {
	return sc.currKeyID
}

func (sc *searchConnector) SetCurrentKeyID(id string) {
	sc.currKeyID = id
}

func (sc *searchConnector) fetchKey(id string) (kID string, key kem.Kem, err error) {
	log.Printf("Fetching envelope key \"%s\" from search\n", id)
	var req *http.Request
	if req, err = http.NewRequest(http.MethodGet, fmt.Sprintf("https://localhost:8890/%s", id), nil); err != nil {
		return
	}
	var response *http.Response
	if response, err = sc.client.Do(req); err != nil {
		return
	}
	bodyBytes, _ := io.ReadAll(response.Body)
	response.Body.Close()
	if response.StatusCode != http.StatusOK {
		err = fmt.Errorf("server returned %d %s", response.StatusCode, bodyBytes)
		return
	}
	type resultType struct {
		KemBytes []byte
		ID       string
	}
	var result resultType
	if err = json.Unmarshal(bodyBytes, &result); err != nil {
		return
	}
	if key, err = kem.UnmarshalKem(result.KemBytes); err == nil {
		kID = result.ID
	}
	return
}
