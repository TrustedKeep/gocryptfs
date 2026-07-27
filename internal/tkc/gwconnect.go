package tkc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/TrustedKeep/tkutils/v2/model"
	"github.com/TrustedKeep/tkutils/v2/tlsutils"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// Operator-provisioned mTLS material is loaded from -gateway-cert-dir under these names.
const (
	gatewayCertFile = "tls.crt"
	gatewayKeyFile  = "tls.key"
	gatewayCAFile   = "ca.crt"
)

// Gateway data-key routes (the gateway serves them under its /api/v1 version prefix). See
// gateway.go for the contract these implement.
const (
	gatewayGeneratePath = "/api/v1/tkfsdatakey/generate"
	gatewayUnwrapPath   = "/api/v1/tkfsdatakey/unwrap"
)

// gwIdleConnTimeout bounds how long an idle keep-alive connection to the gateway is pooled.
const gwIdleConnTimeout = time.Minute

// gwHTTPTimeout bounds a single data-key call.
const gwHTTPTimeout = 10 * time.Second

// maxGatewayResponseBytes bounds a gateway response body. Data-key responses are tiny (a wrapped
// 32-byte key plus small JSON); this cap only stops a misbehaving gateway or proxy from forcing an
// unbounded read.
const maxGatewayResponseBytes = 1 << 20 // 1 MiB

var _ GatewayConnector = (*gwConnector)(nil)

// gwConnector is the real client of the gateway data-key API. It presents an
// operator-provisioned client cert over mTLS and speaks the generate/unwrap contract in
// gateway.go. The cert/key/CA are read once at startup and the mTLS client is built once;
// rotating the cert material requires remounting.
type gwConnector struct {
	host    string // gateway host:port
	nodeID  string // travels in each request; the NodeID half of the DN+NodeID keyspace
	certDir string
	client  *http.Client
	// mockAWS selects where the signed instance identity document attached to data-key
	// requests comes from: a mock AWS session (true) or real AWS IMDS via tkutils/awssession
	// (false). Threaded in now; the document is attached to requests in a later phase.
	mockAWS bool
}

// newGatewayConnector loads the operator-provisioned cert material and builds the mTLS client.
// The first data-key call is what actually dials the gateway. A missing host, cert dir, or
// unreadable/invalid cert set is a fatal misconfiguration.
func newGatewayConnector(host, certDir, nodeID string, mockAWS bool) *gwConnector {
	if host == "" {
		tlog.Fatal.Printf("gateway connector: -gateway-host is required")
		os.Exit(exitcodes.Usage)
	}
	if certDir == "" {
		tlog.Fatal.Printf("gateway connector: -gateway-cert-dir is required")
		os.Exit(exitcodes.Usage)
	}
	if nodeID == "" {
		// The gateway isolates filesystems by keyspace = DN + NodeID; an empty NodeID
		// collapses that isolation. The mock connector rejects it for the same reason.
		tlog.Fatal.Printf("gateway connector: NodeID is required; an empty NodeID defeats keyspace isolation")
		os.Exit(exitcodes.Usage)
	}
	g := &gwConnector{
		host:    host,
		nodeID:  nodeID,
		certDir: certDir,
		mockAWS: mockAWS,
	}
	if err := g.load(); err != nil {
		tlog.Fatal.Printf("gateway connector: %v", err)
		os.Exit(exitcodes.Other)
	}
	return g
}

// load reads the operator-provisioned cert files and builds the mTLS http.Client. It runs once
// at construction and the client is never swapped afterward, so it needs no locking. All three
// files (client cert, key, CA) must be present and the CA must be non-empty.
func (g *gwConnector) load() error {
	certPath := filepath.Join(g.certDir, gatewayCertFile)
	keyPath := filepath.Join(g.certDir, gatewayKeyFile)
	caPath := filepath.Join(g.certDir, gatewayCAFile)
	certPEM, err := os.ReadFile(certPath)
	if err != nil {
		return fmt.Errorf("reading gateway client cert: %w", err)
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return fmt.Errorf("reading gateway client key: %w", err)
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return fmt.Errorf("reading gateway CA: %w", err)
	}
	// Fail closed: an empty CA makes NewTLSConfigWithCert set InsecureSkipVerify, which
	// would leave the gateway's server cert unverified (plan §5). Require a real CA.
	if len(bytes.TrimSpace(caPEM)) == 0 {
		return fmt.Errorf("gateway CA %s is empty", caPath)
	}
	tlsConfig, err := tlsutils.NewTLSConfigWithCert(keyPEM, certPEM, caPEM)
	if err != nil {
		return fmt.Errorf("building gateway TLS config: %w", err)
	}
	g.client = &http.Client{
		Timeout: gwHTTPTimeout,
		Transport: &http.Transport{
			MaxIdleConns:    1,
			MaxConnsPerHost: 2,
			IdleConnTimeout: gwIdleConnTimeout,
			TLSClientConfig: tlsConfig,
		},
	}
	tlog.Info.Printf("Loaded gateway mTLS certificate from %s", g.certDir)
	tlog.Debug.Printf("gateway connector: instance-identity source=%s",
		map[bool]string{true: "mock", false: "AWS IMDS"}[g.mockAWS])
	return nil
}

// GenerateTKFSDataKey mints a fresh gateway-wrapped master key.
func (g *gwConnector) GenerateTKFSDataKey() (TKFSDataKey, error) {
	var out model.TKFSDataKeyGenerateResponse
	if err := g.post(gatewayGeneratePath, model.TKFSDataKeyGenerateRequest{NodeID: g.nodeID}, &out); err != nil {
		return TKFSDataKey{}, err
	}
	if out.KeyID == "" || len(out.Ciphertext) == 0 {
		return TKFSDataKey{}, fmt.Errorf("gateway generate: incomplete response (keyID=%q, ciphertext=%dB)", out.KeyID, len(out.Ciphertext))
	}
	if len(out.Plaintext) != tkfsDataKeyLength {
		return TKFSDataKey{}, fmt.Errorf("gateway generate: expected %d-byte data key, got %d", tkfsDataKeyLength, len(out.Plaintext))
	}
	return TKFSDataKey{KeyID: out.KeyID, Plaintext: out.Plaintext, Ciphertext: out.Ciphertext}, nil
}

// UnwrapTKFSDataKey recovers the plaintext master key for a key-ring entry.
func (g *gwConnector) UnwrapTKFSDataKey(keyID string, ciphertext []byte) ([]byte, error) {
	if keyID == "" {
		return nil, fmt.Errorf("gateway unwrap: empty key id")
	}
	var out model.TKFSDataKeyUnwrapResponse
	if err := g.post(gatewayUnwrapPath, model.TKFSDataKeyUnwrapRequest{NodeID: g.nodeID, KeyID: keyID, Ciphertext: ciphertext}, &out); err != nil {
		return nil, err
	}
	if len(out.Plaintext) != tkfsDataKeyLength {
		return nil, fmt.Errorf("gateway unwrap: expected %d-byte data key, got %d", tkfsDataKeyLength, len(out.Plaintext))
	}
	return out.Plaintext, nil
}

// Close releases idle connections to the gateway.
func (g *gwConnector) Close() error {
	if g.client != nil {
		g.client.CloseIdleConnections()
	}
	return nil
}

// post sends body as JSON to a gateway route and decodes the JSON response. A non-2xx
// status is an error; a 401/403 (the cert DN is not in the gateway ACL) is called out
// explicitly so the operator sees the authorization failure.
func (g *gwConnector) post(path string, body, out any) error {
	if g.client == nil {
		return fmt.Errorf("gateway client not initialized")
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	req, err := http.NewRequest(http.MethodPost, "https://"+g.host+path, bytes.NewReader(buf))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := g.client.Do(req)
	if err != nil {
		return fmt.Errorf("gateway %s: %w", path, err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(io.LimitReader(resp.Body, maxGatewayResponseBytes))
	if err != nil {
		return fmt.Errorf("gateway %s: reading response: %w", path, err)
	}
	switch {
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("gateway %s: not authorized (HTTP %d): cert DN is not in the ACL: %s", path, resp.StatusCode, bytes.TrimSpace(respBody))
	case resp.StatusCode < 200 || resp.StatusCode >= 300:
		return fmt.Errorf("gateway %s: HTTP %d: %s", path, resp.StatusCode, bytes.TrimSpace(respBody))
	}
	if err := json.Unmarshal(respBody, out); err != nil {
		return fmt.Errorf("gateway %s: decoding response: %w", path, err)
	}
	return nil
}
