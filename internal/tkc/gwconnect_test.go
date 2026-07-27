package tkc

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/TrustedKeep/tkutils/v2/certutil"
	"github.com/TrustedKeep/tkutils/v2/kem"
	"github.com/TrustedKeep/tkutils/v2/model"
)

// wrapForTransport is the gateway side of the transit wrap: it OAEP-encrypts dek to the client's
// ephemeral transport public key. In production this lives in the gateway (keep); here it lets the
// test server exercise the whole wrap/unwrap path without a real gateway.
func wrapForTransport(alg uint16, pubPEM, dek []byte) ([]byte, error) {
	switch kem.KemType(alg) {
	case kem.RSA2048, kem.RSA3072, kem.RSA4096:
		pub, err := certutil.ParsePublicKey(pubPEM)
		if err != nil {
			return nil, fmt.Errorf("parse transport key: %w", err)
		}
		rp, ok := pub.(*rsa.PublicKey)
		if !ok {
			return nil, errors.New("transport key is not RSA")
		}
		return rsa.EncryptOAEP(sha256.New(), rand.Reader, rp, dek, nil)
	default:
		return nil, fmt.Errorf("unsupported transport alg %d", alg)
	}
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
			_ = json.NewEncoder(w).Encode(model.TKFSDataKeyGenerateResponse{KeyID: "key-1", Ciphertext: ciphertext, WrappedKey: wrapped})
		case gatewayUnwrapPath:
			_ = json.NewDecoder(r.Body).Decode(&unwReq)
			wrapped, err := wrapForTransport(unwReq.TransportAlg, unwReq.TransportPubKey, master)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(model.TKFSDataKeyUnwrapResponse{WrappedKey: wrapped})
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
		respBody, _ = json.Marshal(model.TKFSDataKeyGenerateResponse{KeyID: "key-1", Ciphertext: ciphertext, WrappedKey: wrapped})
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
	if bytes.Contains(reqBody, master) {
		t.Error("plaintext data key leaked into the request body")
	}
	if bytes.Contains(respBody, master) {
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
	got, err := unwrapTransport(k, wrapped)
	if err != nil {
		t.Fatalf("unwrapTransport: %v", err)
	}
	if !bytes.Equal(got, dek) {
		t.Fatal("round-tripped data key mismatch")
	}

	other, _, err := newTransport()
	if err != nil {
		t.Fatalf("newTransport (other): %v", err)
	}
	if _, err := unwrapTransport(other, wrapped); err == nil {
		t.Fatal("expected unwrap with the wrong transport key to fail closed")
	}
	if _, err := unwrapTransport(k, nil); err == nil {
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
