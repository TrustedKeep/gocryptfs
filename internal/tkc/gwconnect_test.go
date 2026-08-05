package tkc

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TrustedKeep/tkutils/v2/model"
)

// wrapForTransport is the gateway side of the transit wrap in this test's fake server. It delegates to
// the shared model.TransitWrap so the test drives the exact production transit path (RSA-OAEP, the
// inverse of the client's model.TransitUnwrap). In production this same call lives in keep and gatehouse.
func wrapForTransport(alg uint16, pubPEM, dek []byte) ([]byte, error) {
	return model.TransitWrap(alg, pubPEM, dek)
}

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
			wrapped, err := wrapForTransport(genReq.TransportAlg, genReq.TransportPubKey, master)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(model.TKFSDataKeyGenerateResponse{KeyID: "key-1", Ciphertext: ciphertext, TransitWrappedKey: wrapped})
		case gatewayUnwrapPath:
			_ = json.NewDecoder(r.Body).Decode(&unwReq)
			wrapped, err := wrapForTransport(unwReq.TransportAlg, unwReq.TransportPubKey, master)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(model.TKFSDataKeyUnwrapResponse{TransitWrappedKey: wrapped})
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
	if genReq.TransportAlg != uint16(transportKemType) || len(genReq.TransportPubKey) == 0 {
		t.Errorf("generate request missing transport key: alg=%d pub=%dB", genReq.TransportAlg, len(genReq.TransportPubKey))
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
	if unwReq.TransportAlg != uint16(transportKemType) || len(unwReq.TransportPubKey) == 0 {
		t.Errorf("unwrap request missing transport key: alg=%d pub=%dB", unwReq.TransportAlg, len(unwReq.TransportPubKey))
	}
}

// TestGatewayConnectorNoPlaintextOnWire asserts the raw data key never appears in the marshaled
// request or response bodies — only its OAEP-wrapped form does.
func TestGatewayConnectorNoPlaintextOnWire(t *testing.T) {
	master := make([]byte, tkfsDataKeyLength)
	for i := range master {
		master[i] = byte(0xA0 + i) // distinctive, all-nonzero
	}
	ciphertext := []byte("wrapped-master-key")

	var reqBody, respBody []byte
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reqBody, _ = io.ReadAll(r.Body)
		var req model.TKFSDataKeyGenerateRequest
		if err := json.Unmarshal(reqBody, &req); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		wrapped, err := wrapForTransport(req.TransportAlg, req.TransportPubKey, master)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		respBody, _ = json.Marshal(model.TKFSDataKeyGenerateResponse{KeyID: "key-1", Ciphertext: ciphertext, TransitWrappedKey: wrapped})
		_, _ = w.Write(respBody)
	}))
	defer ts.Close()

	g := newTestGWConnector(ts, "node-1")
	dk, err := g.GenerateTKFSDataKey()
	if err != nil {
		t.Fatalf("GenerateTKFSDataKey: %v", err)
	}
	if !bytes.Equal(dk.Plaintext, master) {
		t.Fatal("client did not recover the master key")
	}
	// JSON encodes []byte as base64, so a leaked plaintext key would appear on the wire in its
	// base64 form, not as raw bytes; assert against that (a raw-bytes search would pass trivially
	// and prove nothing).
	masterB64 := []byte(base64.StdEncoding.EncodeToString(master))
	if bytes.Contains(reqBody, masterB64) {
		t.Error("plaintext data key leaked into the request body")
	}
	if bytes.Contains(respBody, masterB64) {
		t.Error("plaintext data key leaked into the response body")
	}
}

// TestTransitWrapRoundTrip exercises the wrap/unwrap primitives directly: a fresh key recovers the
// data key, a different key fails closed, and an empty wrap is rejected.
func TestTransitWrapRoundTrip(t *testing.T) {
	k, pubPEM, err := newTransport()
	if err != nil {
		t.Fatalf("newTransport: %v", err)
	}
	dek := make([]byte, tkfsDataKeyLength)
	for i := range dek {
		dek[i] = byte(0x5A ^ i)
	}
	wrapped, err := wrapForTransport(uint16(transportKemType), pubPEM, dek)
	if err != nil {
		t.Fatalf("wrapForTransport: %v", err)
	}
	got, err := unwrapTransit(k, wrapped)
	if err != nil {
		t.Fatalf("unwrapTransit: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("round-tripped data key mismatch")
	}

	other, _, err := newTransport()
	if err != nil {
		t.Fatalf("newTransport (other): %v", err)
	}
	if _, err := unwrapTransit(other, wrapped); err == nil {
		t.Fatal("expected unwrap with the wrong transport key to fail closed")
	}
	if _, err := unwrapTransit(k, nil); err == nil {
		t.Fatal("expected an empty wrapped key to be rejected")
	}
}

func TestWrapForTransportUnsupportedAlg(t *testing.T) {
	if _, err := wrapForTransport(0, nil, make([]byte, tkfsDataKeyLength)); err == nil {
		t.Fatal("expected an error for unsupported transport alg 0")
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
