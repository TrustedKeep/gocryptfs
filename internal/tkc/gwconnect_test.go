package tkc

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TrustedKeep/tkutils/v2/model"
)

// newTestGWConnector wires a gwConnector to a TLS test server, skipping the cert-loading
// machinery so the data-key logic can be tested directly.
func newTestGWConnector(ts *httptest.Server, nodeID string) *gwConnector {
	return &gwConnector{
		host:   strings.TrimPrefix(ts.URL, "https://"),
		nodeID: nodeID,
		client: ts.Client(),
	}
}

func TestGatewayConnectorGenerateUnwrap(t *testing.T) {
	master := make([]byte, tkfsDataKeyLength)
	for i := range master {
		master[i] = byte(i)
	}
	ciphertext := []byte("wrapped-master-key")

	var genReq model.TKFSDataKeyGenerateRequest
	var unwReq model.TKFSDataKeyUnwrapRequest
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case gatewayGeneratePath:
			_ = json.NewDecoder(r.Body).Decode(&genReq)
			_ = json.NewEncoder(w).Encode(model.TKFSDataKeyGenerateResponse{KeyID: "key-1", Plaintext: master, Ciphertext: ciphertext})
		case gatewayUnwrapPath:
			_ = json.NewDecoder(r.Body).Decode(&unwReq)
			_ = json.NewEncoder(w).Encode(model.TKFSDataKeyUnwrapResponse{Plaintext: master})
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer ts.Close()

	g := newTestGWConnector(ts, "node-1")

	dk, err := g.GenerateTKFSDataKey()
	if err != nil {
		t.Fatalf("GenerateTKFSDataKey: %v", err)
	}
	if dk.KeyID != "key-1" || !bytes.Equal(dk.Plaintext, master) || !bytes.Equal(dk.Ciphertext, ciphertext) {
		t.Fatalf("unexpected data key: %+v", dk)
	}
	if genReq.NodeID != "node-1" {
		t.Errorf("generate request NodeID = %q, want node-1", genReq.NodeID)
	}

	pt, err := g.UnwrapTKFSDataKey("key-1", ciphertext)
	if err != nil {
		t.Fatalf("UnwrapTKFSDataKey: %v", err)
	}
	if !bytes.Equal(pt, master) {
		t.Fatalf("unwrap plaintext mismatch")
	}
	if unwReq.NodeID != "node-1" || unwReq.KeyID != "key-1" || !bytes.Equal(unwReq.Ciphertext, ciphertext) {
		t.Errorf("unexpected unwrap request: %+v", unwReq)
	}
}

func TestGatewayConnectorACLReject(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "DN not allowlisted", http.StatusForbidden)
	}))
	defer ts.Close()

	g := newTestGWConnector(ts, "node-1")
	if _, err := g.GenerateTKFSDataKey(); err == nil {
		t.Fatal("expected an error when the gateway returns 403")
	} else if !strings.Contains(err.Error(), "not authorized") || !strings.Contains(err.Error(), "403") {
		t.Fatalf("error should call out the ACL rejection, got: %v", err)
	}
}

func TestGatewayConnectorUnwrapEmptyKeyID(t *testing.T) {
	g := &gwConnector{}
	if _, err := g.UnwrapTKFSDataKey("", []byte("x")); err == nil {
		t.Fatal("expected an error for an empty key id")
	}
}

func TestGatewayConnectorLoadMissingCert(t *testing.T) {
	g := &gwConnector{certDir: t.TempDir()}
	if err := g.load(); err == nil {
		t.Fatal("expected an error when the cert files are missing")
	}
}
