package tkc

import (
	"bytes"
	"encoding/json"
	"fmt"
	"go/build"
	"io"
	"math/rand"
	"net/http"
	"os"
	"time"

	"github.com/TrustedKeep/tkutils/v2/diskutil"
	"github.com/TrustedKeep/tkutils/v2/kmsclient"
	"github.com/TrustedKeep/tkutils/v2/model"
	"github.com/TrustedKeep/tkutils/v2/tlsutils"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

var _ DataKeyConnector = (*searchConnector)(nil)

// TrustedSearch ramdisk file names. lizard's connector writes these to a tmpfs before launching
// gocryptfs; the search connector reads them here. Same contract as the envelope-era connector.
const (
	searchRamdiskDefault = "/usr/local/trustedsearch/ramdisk"
	searchCertFile       = "gw.cert.pem"
	searchKeyFile        = "gw.key.pem"
	searchCAFile         = "gw.ca.pem"
	searchTokenFile      = "gw.token"
	searchHostsFile      = "gw.hosts.json"
)

// TrustedSearch KMS data-key routes. keep serves them under its /keepsvc prefix on the
// management port; the client authenticates with the ramdisk mTLS cert plus a tenant token.
const (
	searchKMSPort      = 7070
	searchGeneratePath = "/keepsvc/tenantdatakey/generate"
	searchUnwrapPath   = "/keepsvc/tenantdatakey/unwrap"
)

const searchHTTPTimeout = 10 * time.Second

// searchConnector is the -search client of the KEK data-key API. Unlike the gateway connector it
// talks to the TrustedSearch KMS (keep) directly and authenticates with a tenant token in
// addition to its mTLS client cert, reading that material from the TrustedSearch tmpfs ramdisk.
// It speaks the same generate/unwrap contract (model.TKFSDataKey*) with the same per-call
// transit-wrap (newTransport/unwrapTransit, shared with the gateway connector).
type searchConnector struct {
	nodeID   string
	token    string
	kmsHosts []string
	client   *http.Client
}

// newSearchConnector loads the ramdisk-provisioned material and builds the mTLS client. lizard
// writes the ramdisk before launching gocryptfs, so a missing/empty file set is a fatal
// misconfiguration. Data-key calls happen only at mount start, so the material is read
// once; a remount picks up rotated certs.
func newSearchConnector(nodeID string) *searchConnector {
	if nodeID == "" {
		tlog.Fatal.Printf("search connector: NodeID is required")
		os.Exit(exitcodes.Usage)
	}
	ramdisk := searchRamdiskDefault
	if _, err := os.Stat(ramdisk); err != nil {
		if goPath := build.Default.GOPATH; goPath != "" {
			ramdisk = fmt.Sprintf("%s/src/github.com/TrustedKeep/lizard/local/ramdisk", goPath)
			diskutil.EnsureDir(ramdisk)
		}
	}
	s := &searchConnector{nodeID: nodeID}
	if err := s.load(ramdisk); err != nil {
		tlog.Fatal.Printf("search connector: %v", err)
		os.Exit(exitcodes.Other)
	}
	return s
}

func (s *searchConnector) load(ramdisk string) error {
	read := func(name string) ([]byte, error) {
		return os.ReadFile(fmt.Sprintf("%s/%s", ramdisk, name))
	}
	certPEM, err := read(searchCertFile)
	if err != nil {
		return fmt.Errorf("reading search client cert: %w", err)
	}
	keyPEM, err := read(searchKeyFile)
	if err != nil {
		return fmt.Errorf("reading search client key: %w", err)
	}
	caPEM, err := read(searchCAFile)
	if err != nil {
		return fmt.Errorf("reading search CA: %w", err)
	}
	// Fail closed: an empty CA makes NewTLSConfigWithCert set InsecureSkipVerify.
	if len(bytes.TrimSpace(caPEM)) == 0 {
		return fmt.Errorf("search CA is empty")
	}
	tokenBytes, err := read(searchTokenFile)
	if err != nil {
		return fmt.Errorf("reading search tenant token: %w", err)
	}
	hostsData, err := read(searchHostsFile)
	if err != nil {
		return fmt.Errorf("reading search KMS hosts: %w", err)
	}
	var hosts []string
	if err := json.Unmarshal(hostsData, &hosts); err != nil {
		return fmt.Errorf("parsing search KMS hosts: %w", err)
	}
	if len(hosts) == 0 {
		return fmt.Errorf("search KMS host list is empty")
	}
	tlsConfig, err := tlsutils.NewTLSConfigWithCert(keyPEM, certPEM, caPEM)
	if err != nil {
		return fmt.Errorf("building search TLS config: %w", err)
	}
	s.token = string(bytes.TrimSpace(tokenBytes))
	s.kmsHosts = hosts
	s.client = &http.Client{
		Timeout: searchHTTPTimeout,
		Transport: &http.Transport{
			MaxIdleConns:    1,
			MaxConnsPerHost: 2,
			IdleConnTimeout: time.Minute,
			TLSClientConfig: tlsConfig,
		},
	}
	tlog.Info.Printf("Loaded TrustedSearch mTLS material from %s (%d KMS hosts)", ramdisk, len(hosts))
	return nil
}

// GenerateTKFSDataKey mints a fresh KMS-wrapped master key, returned transit-wrapped to a
// per-call ephemeral key and recovered in memory.
func (s *searchConnector) GenerateTKFSDataKey() (TKFSDataKey, error) {
	k, pubPEM, err := newTransport()
	if err != nil {
		return TKFSDataKey{}, fmt.Errorf("search generate: transport keygen: %w", err)
	}
	req := model.TKFSDataKeyGenerateRequest{
		NodeID:          s.nodeID,
		TransportAlg:    uint16(transportKemType),
		TransportPubKey: pubPEM,
	}
	var out model.TKFSDataKeyGenerateResponse
	if err := s.post(searchGeneratePath, req, &out); err != nil {
		return TKFSDataKey{}, err
	}
	if out.KeyID == "" || len(out.Ciphertext) == 0 {
		return TKFSDataKey{}, fmt.Errorf("search generate: incomplete response (keyID=%q, ciphertext=%dB)", out.KeyID, len(out.Ciphertext))
	}
	dek, err := unwrapTransit(k, out.TransitWrappedKey)
	if err != nil {
		return TKFSDataKey{}, fmt.Errorf("search generate: %w", err)
	}
	return TKFSDataKey{KeyID: out.KeyID, Plaintext: dek, Ciphertext: out.Ciphertext}, nil
}

// UnwrapTKFSDataKey recovers the plaintext master key for a key-ring entry.
func (s *searchConnector) UnwrapTKFSDataKey(keyID string, ciphertext []byte) ([]byte, error) {
	if keyID == "" {
		return nil, fmt.Errorf("search unwrap: empty key id")
	}
	k, pubPEM, err := newTransport()
	if err != nil {
		return nil, fmt.Errorf("search unwrap: transport keygen: %w", err)
	}
	req := model.TKFSDataKeyUnwrapRequest{
		NodeID:          s.nodeID,
		KeyID:           keyID,
		Ciphertext:      ciphertext,
		TransportAlg:    uint16(transportKemType),
		TransportPubKey: pubPEM,
	}
	var out model.TKFSDataKeyUnwrapResponse
	if err := s.post(searchUnwrapPath, req, &out); err != nil {
		return nil, err
	}
	dek, err := unwrapTransit(k, out.TransitWrappedKey)
	if err != nil {
		return nil, fmt.Errorf("search unwrap: %w", err)
	}
	return dek, nil
}

// Close releases idle connections to the KMS.
func (s *searchConnector) Close() error {
	if s.client != nil {
		s.client.CloseIdleConnections()
	}
	return nil
}

// post sends body as JSON to a KMS data-key route, trying the configured hosts in random order
// until one answers. Each request carries the tenant token in addition to the mTLS client cert.
// A 401/403 is returned immediately (retrying other hosts will not fix an authorization failure);
// transport and 5xx errors fall through to the next host.
func (s *searchConnector) post(path string, body, out any) error {
	if s.client == nil {
		return fmt.Errorf("search client not initialized")
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	var lastErr error
	for _, idx := range rand.Perm(len(s.kmsHosts)) {
		host := s.kmsHosts[idx]
		url := fmt.Sprintf("https://%s:%d%s", host, searchKMSPort, path)
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(buf))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(kmsclient.HeaderTenantToken, s.token)
		resp, err := s.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("search %s @ %s: %w", path, host, err)
			continue
		}
		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxGatewayResponseBytes))
		resp.Body.Close()
		if readErr != nil {
			lastErr = fmt.Errorf("search %s @ %s: reading response: %w", path, host, readErr)
			continue
		}
		switch {
		case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
			return fmt.Errorf("search %s: not authorized (HTTP %d): tenant token or cert DN rejected: %s", path, resp.StatusCode, bytes.TrimSpace(respBody))
		case resp.StatusCode < 200 || resp.StatusCode >= 300:
			lastErr = fmt.Errorf("search %s @ %s: HTTP %d: %s", path, host, resp.StatusCode, bytes.TrimSpace(respBody))
			continue
		}
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("search %s: decoding response: %w", path, err)
		}
		return nil
	}
	return lastErr
}
