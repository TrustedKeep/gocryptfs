package tkc

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"go/build"
	"io"
	"io/fs"
	"math/rand"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/TrustedKeep/tkutils/v2/diskutil"
	"github.com/TrustedKeep/tkutils/v2/kmsclient"
	"github.com/TrustedKeep/tkutils/v2/model"
	"github.com/TrustedKeep/tkutils/v2/tlsutils"
	"github.com/rfjakob/gocryptfs/v2/internal/exitcodes"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

var (
	_ DataKeyConnector = (*searchConnector)(nil)
	_ Heartbeater      = (*searchConnector)(nil)
)

// TrustedSearch ramdisk file names. lizard's connector writes these to a tmpfs before launching
// gocryptfs; the search connector reads them here.
const (
	searchRamdiskDefault = "/usr/local/trustedsearch/ramdisk"
	searchCertFile       = "gw.cert.pem"
	searchKeyFile        = "gw.key.pem"
	searchCAFile         = "gw.ca.pem"
	searchTokenFile      = "gw.token"
	searchHostsFile      = "gw.hosts.json"
	searchProviderFile   = "gw.provider"
	searchNamespaceFile  = "gw.namespace"
)

// searchProviderNexus is the gw.provider value that selects Nexus; no file, or any other value, selects keep.
const searchProviderNexus = "nexus"

// TrustedSearch KMS data-key routes. keep serves them under its /keepsvc prefix on the
// management port; the client authenticates with the ramdisk mTLS cert plus a tenant token.
const (
	searchKMSPort       = 7070
	searchGeneratePath  = "/keepsvc/tenantdatakey/generate"
	searchUnwrapPath    = "/keepsvc/tenantdatakey/unwrap"
	searchHeartbeatPath = "/keepsvc/tenantdatakey/heartbeat"
)

// Nexus serves the same routes at its search listener's root, where each host carries its own port. The
// caller's namespace travels in a header in place of the tenant token.
const (
	nexusGeneratePath    = "/tkfsdatakey/generate"
	nexusUnwrapPath      = "/tkfsdatakey/unwrap"
	nexusHeartbeatPath   = "/tkfsdatakey/heartbeat"
	nexusNamespaceHeader = "Namespace"
)

// searchProvider is what differs on the wire between keep and Nexus; load picks one from the ramdisk.
type searchProvider struct {
	name string
	// port is appended to each host; Nexus hosts carry their own.
	port                        string
	generate, unwrap, heartbeat string
	// authHeader carries the connector's auth value: keep's tenant token, or the Nexus namespace.
	authHeader string
	// rejected is what a 401 means.
	rejected string
}

var (
	keepSearch = searchProvider{
		name: "keep", port: ":" + strconv.Itoa(searchKMSPort),
		generate: searchGeneratePath, unwrap: searchUnwrapPath, heartbeat: searchHeartbeatPath,
		authHeader: kmsclient.HeaderTenantToken, rejected: "tenant token rejected",
	}
	nexusSearch = searchProvider{
		name:     "Nexus",
		generate: nexusGeneratePath, unwrap: nexusUnwrapPath, heartbeat: nexusHeartbeatPath,
		authHeader: nexusNamespaceHeader, rejected: "client certificate not accepted",
	}
)

const searchHTTPTimeout = 10 * time.Second

// searchConnector is the -search client of the KEK data-key API, served by keep or, when the ramdisk's
// gw.provider says so, by Nexus. keep shares its KEKs with the gateway route; Nexus keeps its own per namespace.
type searchConnector struct {
	nodeID   string
	identity instanceIdentity
	provider searchProvider
	// auth is sent in provider.authHeader on every call unless empty, as it is for Nexus without a namespace.
	auth     string
	kmsHosts []string
	client   *http.Client
}

// newSearchConnector reads the ramdisk lizard writes before launching gocryptfs; missing material is fatal.
// Nothing but identity changes afterwards, so calls read the rest unlocked and new certs need a remount.
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
	nexus, namespace, err := readSearchProvider(read)
	if err != nil {
		return err
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
	provider, auth := nexusSearch, namespace
	if !nexus {
		token, err := read(searchTokenFile)
		if err != nil {
			return fmt.Errorf("reading search tenant token: %w", err)
		}
		provider, auth = keepSearch, string(bytes.TrimSpace(token))
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
	s.provider, s.auth = provider, auth
	s.kmsHosts = hosts
	s.client = &http.Client{
		Timeout: searchHTTPTimeout,
		Transport: &http.Transport{
			MaxIdleConns:    1,
			MaxConnsPerHost: MaxConns,
			IdleConnTimeout: time.Minute,
			TLSClientConfig: tlsConfig,
		},
	}
	switch {
	case nexus && namespace == "":
		tlog.Info.Printf("Loaded TrustedSearch mTLS material from %s (Nexus, no %s so Nexus's default namespace, %d hosts)", ramdisk, searchNamespaceFile, len(hosts))
	case nexus:
		tlog.Info.Printf("Loaded TrustedSearch mTLS material from %s (Nexus, namespace %q, %d hosts)", ramdisk, namespace, len(hosts))
	default:
		tlog.Info.Printf("Loaded TrustedSearch mTLS material from %s (keep, %d KMS hosts)", ramdisk, len(hosts))
	}
	return nil
}

// readSearchProvider reports whether the ramdisk selects Nexus, and with it any namespace to send. A missing
// gw.provider is keep and a missing or blank gw.namespace sends none, but an unreadable file is an error.
func readSearchProvider(read func(string) ([]byte, error)) (nexus bool, namespace string, err error) {
	marker, err := read(searchProviderFile)
	if errors.Is(err, fs.ErrNotExist) {
		return false, "", nil
	}
	if err != nil {
		return false, "", fmt.Errorf("reading search provider: %w", err)
	}
	if strings.TrimSpace(string(marker)) != searchProviderNexus {
		return false, "", nil
	}
	ns, err := read(searchNamespaceFile)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return false, "", fmt.Errorf("reading search namespace: %w", err)
	}
	return true, strings.TrimSpace(string(ns)), nil
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
		KekID:           s.identity.get(),
		TransportAlg:    uint16(transportKemType),
		TransportPubKey: pubPEM,
	}
	var out model.TKFSDataKeyGenerateResponse
	if err := s.post(s.provider.generate, req, &out); err != nil {
		return TKFSDataKey{}, err
	}
	if out.KeyID == "" || len(out.Ciphertext) == 0 {
		return TKFSDataKey{}, fmt.Errorf("search generate: incomplete response (keyID=%q, ciphertext=%dB)", out.KeyID, len(out.Ciphertext))
	}
	if out.CreatedAt.IsZero() {
		return TKFSDataKey{}, fmt.Errorf("search generate: the key service did not stamp the data key's creation time")
	}
	dek, err := unwrapTransit(k, out.TransitWrappedKey)
	if err != nil {
		return TKFSDataKey{}, fmt.Errorf("search generate: %w", err)
	}
	// On a mint this is where the filesystem learns who it is; on a rotation the id is the one we sent.
	if err := s.identity.adopt(out.KeyID); err != nil {
		clear(dek)
		return TKFSDataKey{}, fmt.Errorf("search generate: %w", err)
	}
	return TKFSDataKey{KeyID: out.KeyID, Plaintext: dek, Ciphertext: out.Ciphertext, CreatedAt: out.CreatedAt}, nil
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
	if err := s.post(s.provider.unwrap, req, &out); err != nil {
		return nil, err
	}
	dek, err := unwrapTransit(k, out.TransitWrappedKey)
	if err != nil {
		return nil, fmt.Errorf("search unwrap: %w", err)
	}
	return dek, nil
}

func (s *searchConnector) Heartbeat(event model.TKFSHeartbeatEvent, keyIdx uint16, keyCreatedAt time.Time) (model.TKFSHeartbeatResponse, error) {
	req := model.TKFSHeartbeatRequest{
		NodeID:       s.nodeID,
		KekID:        s.identity.get(),
		KeyIdx:       keyIdx,
		KeyCreatedAt: keyCreatedAt,
		Event:        event,
	}
	var out model.TKFSHeartbeatResponse
	if err := s.post(s.provider.heartbeat, req, &out); err != nil {
		return model.TKFSHeartbeatResponse{}, err
	}
	return out, nil
}

// AdoptIdentity records the identity read out of this filesystem's key ring.
func (s *searchConnector) AdoptIdentity(id string) error {
	return s.identity.adopt(id)
}

// Close releases idle connections to the KMS.
func (s *searchConnector) Close() error {
	if s.client != nil {
		s.client.CloseIdleConnections()
	}
	return nil
}

// keepRedirect returns the page keep points a caller to, "" if body is not a redirect. A sealed keep node
// answers every route it is not serving with 200 and a redirect, which would otherwise decode as an empty answer.
func keepRedirect(body []byte) string {
	var r struct {
		Redirect string `json:"redirect"`
	}
	if json.Unmarshal(body, &r) != nil {
		return ""
	}
	return r.Redirect
}

// post sends body as JSON to the provider's route, trying the hosts in random order until one answers.
// A 401/403 returns at once; anything else, including a 404/501 or a sealed keep node's redirect, tries the
// next host, and ErrNotImplemented is returned only when every host answered 404/501.
func (s *searchConnector) post(path string, body, out any) error {
	if s.client == nil {
		return fmt.Errorf("search client not initialized")
	}
	buf, err := json.Marshal(body)
	if err != nil {
		return err
	}
	var lastErr error
	// credErr is the first credential rejection seen. It is returned over lastErr, so whether this
	// instance was rejected does not depend on which host the random order happened to try last.
	var credErr error
	notImplemented := 0
	for _, idx := range rand.Perm(len(s.kmsHosts)) {
		host := s.kmsHosts[idx]
		url := fmt.Sprintf("https://%s%s%s", host, s.provider.port, path)
		req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(buf))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		if s.auth != "" {
			req.Header.Set(s.provider.authHeader, s.auth)
		}
		resp, err := s.client.Do(req)
		if err != nil {
			lastErr = fmt.Errorf("search %s @ %s: %w", path, host, transportErr(err))
			if credErr == nil && CredentialsRejected(lastErr) {
				credErr = lastErr
			}
			continue
		}
		respBody, readErr := io.ReadAll(io.LimitReader(resp.Body, maxGatewayResponseBytes))
		resp.Body.Close()
		if readErr != nil {
			lastErr = fmt.Errorf("search %s @ %s: reading response: %w", path, host, readErr)
			continue
		}
		switch {
		case resp.StatusCode == http.StatusForbidden:
			// A decision rather than an outage, same as the gateway: the caller must not
			// spend a retry budget on it.
			return fmt.Errorf("search %s: not authorized (HTTP 403): %w: %s", path, ErrDenied, bytes.TrimSpace(respBody))
		case resp.StatusCode == http.StatusUnauthorized:
			return fmt.Errorf("search %s: not authorized (HTTP 401): %s: %w: %s", path, s.provider.rejected, ErrUnauthenticated, bytes.TrimSpace(respBody))
		case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusNotImplemented:
			// A route this host does not serve; another may.
			notImplemented++
			lastErr = fmt.Errorf("search %s @ %s: HTTP %d: %s", path, host, resp.StatusCode, bytes.TrimSpace(respBody))
			continue
		case resp.StatusCode < 200 || resp.StatusCode >= 300:
			lastErr = fmt.Errorf("search %s @ %s: HTTP %d: %s", path, host, resp.StatusCode, bytes.TrimSpace(respBody))
			continue
		}
		if page := keepRedirect(respBody); page != "" {
			lastErr = fmt.Errorf("search %s @ %s: keep redirected to %s instead of answering; it may be sealed", path, host, page)
			continue
		}
		if err := json.Unmarshal(respBody, out); err != nil {
			return fmt.Errorf("search %s: decoding response: %w", path, err)
		}
		return nil
	}
	if credErr != nil {
		return credErr
	}
	if notImplemented == len(s.kmsHosts) {
		return fmt.Errorf("%w: %v", ErrNotImplemented, lastErr)
	}
	return lastErr
}
