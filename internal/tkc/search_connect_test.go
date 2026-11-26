package tkc

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/TrustedKeep/tkutils/v2/kmsclient"
	"github.com/TrustedKeep/tkutils/v2/model"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return f(r) }

// newTestSearchConnector answers every request from rt, skipping the ramdisk material and the
// hardcoded KMS port so the route and body logic can be tested directly.
func newTestSearchConnector(rt roundTripFunc) *searchConnector {
	return &searchConnector{
		nodeID:   "node-1",
		provider: keepSearch,
		auth:     "tenant-token",
		kmsHosts: []string{"kms-1"},
		client:   &http.Client{Transport: rt},
	}
}

// newTestNexusConnector is newTestSearchConnector under the Nexus marker; its host carries the port.
func newTestNexusConnector(rt roundTripFunc) *searchConnector {
	s := newTestSearchConnector(rt)
	s.provider, s.auth, s.kmsHosts = nexusSearch, "ns-1", []string{"nexus-1:9082"}
	return s
}

func jsonResponse(code int, v any) *http.Response {
	body, _ := json.Marshal(v)
	return &http.Response{StatusCode: code, Body: io.NopCloser(bytes.NewReader(body)), Header: http.Header{}}
}

// A search mount heartbeats to keep exactly as a gateway-proxied one does to the gateway: same body,
// same pass-through of a rekey directive, and the same three failure classes. 403 is revocation,
// 404/501 is a keep that does not serve the route, and everything else is an outage. The caller suspends
// at once on a 403 and counts the others as failures.
func TestSearchConnectorHeartbeat(t *testing.T) {
	var got model.TKFSHeartbeatRequest
	var status int
	s := newTestSearchConnector(func(r *http.Request) (*http.Response, error) {
		if r.URL.Path != searchHeartbeatPath {
			t.Errorf("path = %q, want %q", r.URL.Path, searchHeartbeatPath)
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		if status != 0 {
			return jsonResponse(status, "nope"), nil
		}
		return jsonResponse(http.StatusOK, model.TKFSHeartbeatResponse{Command: model.TKFSCommandRekey}), nil
	})
	s.identity.adopt("instance-1")

	resp, err := s.Heartbeat(model.TKFSEventUnmount, 7, testCreatedAt)
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if got.NodeID != "node-1" || got.KekID != "instance-1" || got.KeyIdx != 7 || !got.KeyCreatedAt.Equal(testCreatedAt) ||
		got.Event != model.TKFSEventUnmount {
		t.Errorf("request = %+v, want the node, instance, key-ring index, key stamp and event", got)
	}
	if resp.Command != model.TKFSCommandRekey {
		t.Errorf("response = %+v, want the command passed through", resp)
	}

	status = http.StatusForbidden
	if _, err := s.Heartbeat(model.TKFSEventNone, 0, testCreatedAt); !errors.Is(err, ErrDenied) {
		t.Errorf("403 error = %v, want one wrapping ErrDenied", err)
	}
	for _, code := range []int{http.StatusNotFound, http.StatusNotImplemented} {
		status = code
		_, err := s.Heartbeat(model.TKFSEventNone, 0, testCreatedAt)
		if !errors.Is(err, ErrNotImplemented) {
			t.Errorf("%d error = %v, want one wrapping ErrNotImplemented", code, err)
		}
		if errors.Is(err, ErrDenied) {
			t.Errorf("%d must not read as a denial: %v", code, err)
		}
	}
	status = http.StatusServiceUnavailable
	if _, err := s.Heartbeat(model.TKFSEventNone, 0, testCreatedAt); err == nil {
		t.Error("503 must be an error")
	} else if errors.Is(err, ErrDenied) || errors.Is(err, ErrNotImplemented) {
		t.Errorf("503 must read as a plain outage: %v", err)
	}
}

// One keep host without the route, or a proxy 404 in front of it, does not end the call: the next host
// is tried, and ErrNotImplemented comes back only when every host answered 404/501.
func TestSearchConnectorTriesTheNextHostOnA404(t *testing.T) {
	s := newTestSearchConnector(func(r *http.Request) (*http.Response, error) {
		if r.URL.Hostname() == "kms-old" {
			return jsonResponse(http.StatusNotFound, "404 page not found"), nil
		}
		return jsonResponse(http.StatusOK, model.TKFSHeartbeatResponse{}), nil
	})
	s.identity.adopt("instance-1")
	s.kmsHosts = []string{"kms-old", "kms-1"}
	for i := 0; i < 20; i++ { // hosts are tried in random order
		if _, err := s.Heartbeat(model.TKFSEventNone, 0, testCreatedAt); err != nil {
			t.Fatalf("one host without the route failed the call: %v", err)
		}
	}
	s.kmsHosts = []string{"kms-old", "kms-old"}
	if _, err := s.Heartbeat(model.TKFSEventNone, 0, testCreatedAt); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("every host 404 = %v, want ErrNotImplemented", err)
	}
}

// A sealed keep node answers 200 with a redirect to its unseal page. That is no answer: the next host is
// tried, and when every host is sealed the call fails as an outage.
func TestSearchConnectorSkipsASealedNode(t *testing.T) {
	s := newTestSearchConnector(func(r *http.Request) (*http.Response, error) {
		if r.URL.Hostname() == "kms-sealed" {
			return jsonResponse(http.StatusOK, map[string]string{"redirect": "/v2/#/seal"}), nil
		}
		return jsonResponse(http.StatusOK, model.TKFSHeartbeatResponse{Command: model.TKFSCommandRekey}), nil
	})
	s.identity.adopt("instance-1")
	s.kmsHosts = []string{"kms-sealed", "kms-1"}
	for i := 0; i < 20; i++ { // hosts are tried in random order
		resp, err := s.Heartbeat(model.TKFSEventNone, 0, testCreatedAt)
		if err != nil || resp.Command != model.TKFSCommandRekey {
			t.Fatalf("got %+v, %v; want the unsealed host's answer", resp, err)
		}
	}
	s.kmsHosts = []string{"kms-sealed", "kms-sealed"}
	_, err := s.Heartbeat(model.TKFSEventNone, 0, testCreatedAt)
	if err == nil {
		t.Fatal("every host sealed must fail the call")
	}
	if errors.Is(err, ErrDenied) || errors.Is(err, ErrNotImplemented) || CredentialsRejected(err) {
		t.Errorf("every host sealed = %v, want a plain outage", err)
	}
}

// When one host rejects this instance's certificate and another is unreachable, the rejection is what
// comes back, whatever order the hosts were tried in: it decides the exit code systemd acts on.
func TestSearchConnectorPrefersACredentialRejection(t *testing.T) {
	s := newTestSearchConnector(func(r *http.Request) (*http.Response, error) {
		if r.URL.Hostname() == "kms-rejects" {
			return nil, errors.New("remote error: tls: unknown certificate authority")
		}
		return nil, errors.New("dial tcp: i/o timeout")
	})
	s.identity.adopt("instance-1")
	s.kmsHosts = []string{"kms-rejects", "kms-down"}
	for i := 0; i < 20; i++ { // hosts are tried in random order
		_, err := s.Heartbeat(model.TKFSEventNone, 0, testCreatedAt)
		if !CredentialsRejected(err) {
			t.Fatalf("attempt %d: err = %v, want the credential rejection", i, err)
		}
	}
}

// A TLS alert refusing the client certificate is a credential rejection only where the request failed:
// every alert a server or terminator sends for it is recognized, and a 5xx body that quotes an upstream
// TLS failure is not.
func TestCredentialRejectionComesFromTheTransportOnly(t *testing.T) {
	for _, alert := range []string{
		"remote error: tls: bad certificate",
		"remote error: tls: unknown certificate authority",
		"remote error: tls: unknown certificate",
		"remote error: tls: unsupported certificate",
		"remote error: tls: certificate required",
	} {
		s := newTestSearchConnector(func(*http.Request) (*http.Response, error) { return nil, errors.New(alert) })
		s.identity.adopt("instance-1")
		if _, err := s.Heartbeat(model.TKFSEventNone, 0, testCreatedAt); !CredentialsRejected(err) {
			t.Errorf("%q from the transport: CredentialsRejected = false", alert)
		}
	}
	s := newTestSearchConnector(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusBadGateway, "dial upstream: remote error: tls: bad certificate"), nil
	})
	s.identity.adopt("instance-1")
	if _, err := s.Heartbeat(model.TKFSEventNone, 0, testCreatedAt); err == nil || CredentialsRejected(err) {
		t.Errorf("a 502 quoting a TLS error: err = %v, want an outage, not a credential rejection", err)
	}
}

// The tenant token authenticates the call alongside the mTLS cert, so every route has to carry it.
func TestSearchConnectorSendsTenantToken(t *testing.T) {
	var token string
	s := newTestSearchConnector(func(r *http.Request) (*http.Response, error) {
		token = r.Header.Get(kmsclient.HeaderTenantToken)
		return jsonResponse(http.StatusOK, model.TKFSHeartbeatResponse{}), nil
	})
	if _, err := s.Heartbeat(model.TKFSEventNone, 0, testCreatedAt); err != nil {
		t.Fatal(err)
	}
	if token != "tenant-token" {
		t.Errorf("token header = %q, want the connector's token", token)
	}
}

// Generate returns the key service's stamp, and refuses a key that carries none.
func TestSearchConnectorGenerateStamp(t *testing.T) {
	var createdAt time.Time
	s := newTestSearchConnector(func(r *http.Request) (*http.Response, error) {
		var req model.TKFSDataKeyGenerateRequest
		_ = json.NewDecoder(r.Body).Decode(&req)
		wrapped, err := wrapForTransport(req.TransportAlg, req.TransportPubKey, make([]byte, tkfsDataKeyLength))
		if err != nil {
			return nil, err
		}
		return jsonResponse(http.StatusOK, model.TKFSDataKeyGenerateResponse{
			KeyID: "kek-1", Ciphertext: []byte("ct"), TransitWrappedKey: wrapped, CreatedAt: createdAt,
		}), nil
	})

	if _, err := s.GenerateTKFSDataKey(); err == nil {
		t.Error("a generate with no CreatedAt must fail")
	}
	if got := s.identity.get(); got != "" {
		t.Errorf("identity = %q after a refused mint, want none", got)
	}
	createdAt = testCreatedAt
	dk, err := s.GenerateTKFSDataKey()
	if err != nil {
		t.Fatal(err)
	}
	if !dk.CreatedAt.Equal(testCreatedAt) {
		t.Errorf("CreatedAt = %v, want the key service's %v", dk.CreatedAt, testCreatedAt)
	}
}

// Only a trimmed "nexus" selects Nexus, with or without a namespace. A ramdisk without the marker is keep's.
func TestReadSearchProvider(t *testing.T) {
	files := func(m map[string]string) func(string) ([]byte, error) {
		return func(name string) ([]byte, error) {
			if v, ok := m[name]; ok {
				return []byte(v), nil
			}
			return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
		}
	}
	for _, tc := range []struct {
		name      string
		read      func(string) ([]byte, error)
		nexus     bool
		namespace string
		fails     bool
	}{
		{"no marker", files(nil), false, "", false},
		{"nexus", files(map[string]string{searchProviderFile: searchProviderNexus + "\n", searchNamespaceFile: " ns-1\n"}), true, "ns-1", false},
		{"other value", files(map[string]string{searchProviderFile: "keep", searchNamespaceFile: "ns-1"}), false, "", false},
		{"other case", files(map[string]string{searchProviderFile: strings.ToUpper(searchProviderNexus)}), false, "", false},
		{"empty marker", files(map[string]string{searchProviderFile: ""}), false, "", false},
		{"no namespace", files(map[string]string{searchProviderFile: searchProviderNexus}), true, "", false},
		{"blank namespace", files(map[string]string{searchProviderFile: searchProviderNexus, searchNamespaceFile: " \n"}), true, "", false},
		{"unreadable marker", func(name string) ([]byte, error) {
			return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
		}, false, "", true},
		{"unreadable namespace", func(name string) ([]byte, error) {
			if name == searchProviderFile {
				return []byte(searchProviderNexus), nil
			}
			return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrPermission}
		}, false, "", true},
	} {
		nexus, ns, err := readSearchProvider(tc.read)
		if (err != nil) != tc.fails || nexus != tc.nexus || ns != tc.namespace {
			t.Errorf("%s: got (%v, %q, %v), want (%v, %q, fails=%v)", tc.name, nexus, ns, err, tc.nexus, tc.namespace, tc.fails)
		}
	}
}

// writeRamdisk lays out a TrustedSearch ramdisk: writeCertDir's TLS material under its gw.* names, plus files.
func writeRamdisk(t *testing.T, files map[string]string) string {
	t.Helper()
	certDir, dir := writeCertDir(t), t.TempDir()
	for from, to := range map[string]string{gatewayCertFile: searchCertFile, gatewayKeyFile: searchKeyFile, gatewayCAFile: searchCAFile} {
		b, err := os.ReadFile(filepath.Join(certDir, from))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, to), b, 0600); err != nil {
			t.Fatal(err)
		}
	}
	for name, data := range files {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// Without the marker load still needs keep's token. Nexus never reads a token, and loads without a namespace.
func TestSearchConnectorLoadProvider(t *testing.T) {
	keep := &searchConnector{}
	if err := keep.load(writeRamdisk(t, map[string]string{searchTokenFile: "tenant-token\n", searchHostsFile: `["kms-1"]`})); err != nil {
		t.Fatalf("keep: %v", err)
	}
	if keep.provider != keepSearch || keep.auth != "tenant-token" {
		t.Errorf("keep loaded provider=%s auth=%q", keep.provider.name, keep.auth)
	}
	if err := (&searchConnector{}).load(writeRamdisk(t, map[string]string{searchHostsFile: `["kms-1"]`})); err == nil {
		t.Error("keep without a token must fail")
	}

	nexus := &searchConnector{}
	if err := nexus.load(writeRamdisk(t, map[string]string{
		searchProviderFile: searchProviderNexus + "\n", searchNamespaceFile: "ns-1\n", searchHostsFile: `["nexus-1:9082"]`,
	})); err != nil {
		t.Fatalf("nexus: %v", err)
	}
	if nexus.provider != nexusSearch || nexus.auth != "ns-1" || !reflect.DeepEqual(nexus.kmsHosts, []string{"nexus-1:9082"}) {
		t.Errorf("nexus loaded provider=%s auth=%q hosts=%q", nexus.provider.name, nexus.auth, nexus.kmsHosts)
	}
	bare := &searchConnector{}
	if err := bare.load(writeRamdisk(t, map[string]string{
		searchProviderFile: searchProviderNexus, searchTokenFile: "tenant-token", searchHostsFile: `["nexus-1:9082"]`,
	})); err != nil {
		t.Fatalf("nexus without a namespace: %v", err)
	}
	if bare.provider != nexusSearch || bare.auth != "" {
		t.Errorf("nexus without a namespace loaded provider=%s auth=%q", bare.provider.name, bare.auth)
	}
}

// Without a namespace, Nexus calls carry no Namespace header, so Nexus uses its default, as v1 did.
func TestSearchConnectorNexusWithoutNamespace(t *testing.T) {
	var calls []searchCall
	s := newTestNexusConnector(fakeSearchKMS(&calls))
	s.auth = ""
	driveSearch(t, s)
	for _, c := range calls {
		if got := c.header.Values(nexusNamespaceHeader); len(got) != 0 {
			t.Errorf("%s: %s = %q, want none", c.url, nexusNamespaceHeader, got)
		}
	}
}

type searchCall struct {
	url    string
	header http.Header
	body   map[string]any
}

// fakeSearchKMS answers every data-key route of either provider, recording each call.
func fakeSearchKMS(calls *[]searchCall) roundTripFunc {
	return func(r *http.Request) (*http.Response, error) {
		raw, err := io.ReadAll(r.Body)
		if err != nil {
			return nil, err
		}
		call := searchCall{url: r.URL.String(), header: r.Header}
		if err := json.Unmarshal(raw, &call.body); err != nil {
			return nil, err
		}
		*calls = append(*calls, call)
		var req model.TKFSDataKeyUnwrapRequest // the transport fields generate shares
		if err := json.Unmarshal(raw, &req); err != nil {
			return nil, err
		}
		switch r.URL.Path {
		case searchHeartbeatPath, nexusHeartbeatPath:
			return jsonResponse(http.StatusOK, model.TKFSHeartbeatResponse{}), nil
		case searchGeneratePath, nexusGeneratePath, searchUnwrapPath, nexusUnwrapPath:
		default:
			return jsonResponse(http.StatusNotFound, "no such route"), nil
		}
		wrapped, err := wrapForTransport(req.TransportAlg, req.TransportPubKey, make([]byte, tkfsDataKeyLength))
		if err != nil {
			return nil, err
		}
		if r.URL.Path == searchGeneratePath || r.URL.Path == nexusGeneratePath {
			return jsonResponse(http.StatusOK, model.TKFSDataKeyGenerateResponse{
				KeyID: "kek-1", Ciphertext: []byte("ct"), TransitWrappedKey: wrapped, CreatedAt: testCreatedAt,
			}), nil
		}
		return jsonResponse(http.StatusOK, model.TKFSDataKeyUnwrapResponse{TransitWrappedKey: wrapped}), nil
	}
}

func driveSearch(t *testing.T, s *searchConnector) {
	t.Helper()
	if _, err := s.GenerateTKFSDataKey(); err != nil {
		t.Fatalf("generate: %v", err)
	}
	if _, err := s.UnwrapTKFSDataKey("kek-1", []byte("ct")); err != nil {
		t.Fatalf("unwrap: %v", err)
	}
	if _, err := s.Heartbeat(model.TKFSEventNone, 3, testCreatedAt); err != nil {
		t.Fatalf("heartbeat: %v", err)
	}
}

// Nexus gets keep's bodies at its own paths, on the host as given and with a Namespace header in place of the
// token. Without the marker, keep's URLs and headers stay exactly as they were.
func TestSearchConnectorRoutes(t *testing.T) {
	var keepCalls, nexusCalls []searchCall
	driveSearch(t, newTestSearchConnector(fakeSearchKMS(&keepCalls)))
	driveSearch(t, newTestNexusConnector(fakeSearchKMS(&nexusCalls)))

	for _, tc := range []struct {
		name          string
		calls         []searchCall
		urls          []string
		header, value string
		absent        string
	}{
		{"keep", keepCalls, []string{
			"https://kms-1:7070/keepsvc/tenantdatakey/generate",
			"https://kms-1:7070/keepsvc/tenantdatakey/unwrap",
			"https://kms-1:7070/keepsvc/tenantdatakey/heartbeat",
		}, kmsclient.HeaderTenantToken, "tenant-token", nexusNamespaceHeader},
		{"nexus", nexusCalls, []string{
			"https://nexus-1:9082/tkfsdatakey/generate",
			"https://nexus-1:9082/tkfsdatakey/unwrap",
			"https://nexus-1:9082/tkfsdatakey/heartbeat",
		}, nexusNamespaceHeader, "ns-1", kmsclient.HeaderTenantToken},
	} {
		if len(tc.calls) != len(tc.urls) {
			t.Fatalf("%s: %d calls, want %d", tc.name, len(tc.calls), len(tc.urls))
		}
		for i, c := range tc.calls {
			if c.url != tc.urls[i] {
				t.Errorf("%s: URL = %q, want %q", tc.name, c.url, tc.urls[i])
			}
			if got := c.header.Get(tc.header); got != tc.value {
				t.Errorf("%s %s: %s = %q, want %q", tc.name, c.url, tc.header, got, tc.value)
			}
			if got := c.header.Values(tc.absent); len(got) != 0 {
				t.Errorf("%s %s: %s = %q, want none", tc.name, c.url, tc.absent, got)
			}
		}
	}
	for i := range keepCalls {
		k, n := keepCalls[i].body, nexusCalls[i].body
		// The transport key is fresh per call.
		delete(k, "TransportPubKey")
		delete(n, "TransportPubKey")
		if !reflect.DeepEqual(k, n) {
			t.Errorf("%s body = %v, keep's = %v", nexusCalls[i].url, n, k)
		}
	}
}

// Both providers read a status alike. 403 is a denial and 401 a credential failure, both at once; 404 and 501
// are a missing route once every host answers so, and anything else is an outage that tries every host.
func TestSearchConnectorStatusParity(t *testing.T) {
	for _, mode := range []struct {
		name     string
		connect  func(roundTripFunc) *searchConnector
		hosts    []string
		rejected string
	}{
		{"keep", newTestSearchConnector, []string{"kms-1", "kms-2"}, "tenant token"},
		{"nexus", newTestNexusConnector, []string{"nexus-1:9082", "nexus-2:9082"}, "client certificate"},
	} {
		for _, tc := range []struct {
			code  int
			is    error
			calls int
		}{
			{http.StatusForbidden, ErrDenied, 1},
			{http.StatusUnauthorized, ErrUnauthenticated, 1},
			{http.StatusNotFound, ErrNotImplemented, 2},
			{http.StatusNotImplemented, ErrNotImplemented, 2},
			{http.StatusBadRequest, nil, 2},
			{http.StatusInternalServerError, nil, 2},
			{http.StatusBadGateway, nil, 2},
			{http.StatusServiceUnavailable, nil, 2},
		} {
			calls := 0
			s := mode.connect(func(*http.Request) (*http.Response, error) {
				calls++
				return jsonResponse(tc.code, "nope"), nil
			})
			s.kmsHosts = mode.hosts
			_, err := s.Heartbeat(model.TKFSEventNone, 0, testCreatedAt)
			switch {
			case err == nil:
				t.Errorf("%s %d: no error", mode.name, tc.code)
			case tc.is != nil && !errors.Is(err, tc.is):
				t.Errorf("%s %d: %v, want one wrapping %v", mode.name, tc.code, err, tc.is)
			case tc.is == nil && (errors.Is(err, ErrDenied) || errors.Is(err, ErrNotImplemented)):
				t.Errorf("%s %d: %v must be neither a denial nor a missing route", mode.name, tc.code, err)
			case tc.code == http.StatusUnauthorized && !strings.Contains(err.Error(), mode.rejected):
				t.Errorf("%s 401: %v, want it to name the %s", mode.name, err, mode.rejected)
			}
			if calls != tc.calls {
				t.Errorf("%s %d: %d hosts tried, want %d", mode.name, tc.code, calls, tc.calls)
			}
		}
	}
}

// A Nexus host that fails costs nothing when another answers.
func TestSearchConnectorNexusFallsThrough(t *testing.T) {
	for try := 0; try < 100; try++ {
		var hit []string
		s := newTestNexusConnector(func(r *http.Request) (*http.Response, error) {
			hit = append(hit, r.URL.Host)
			if r.URL.Host == "nexus-1:9082" {
				return jsonResponse(http.StatusServiceUnavailable, "down"), nil
			}
			return jsonResponse(http.StatusOK, model.TKFSHeartbeatResponse{}), nil
		})
		s.kmsHosts = []string{"nexus-1:9082", "nexus-2:9082"}
		if _, err := s.Heartbeat(model.TKFSEventNone, 0, testCreatedAt); err != nil {
			t.Fatalf("Heartbeat: %v", err)
		}
		if len(hit) == 2 {
			return
		}
	}
	t.Fatal("the failing host was never tried first")
}
