package tkc

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
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
		token:    "tenant-token",
		kmsHosts: []string{"kms-1"},
		client:   &http.Client{Transport: rt},
	}
}

func jsonResponse(code int, v any) *http.Response {
	body, _ := json.Marshal(v)
	return &http.Response{StatusCode: code, Body: io.NopCloser(bytes.NewReader(body)), Header: http.Header{}}
}

// A search mount heartbeats to keep exactly as a gateway-proxied one does to the gateway: same body,
// same pass-through of a rekey directive, and the same three failure classes. 403 is revocation,
// 404/501 is a keep that does not serve the route, and everything else is an outage — the caller
// unmounts immediately on the first two and spends a failure budget on the third.
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

	resp, err := s.Heartbeat(7, testCreatedAt)
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if got.NodeID != "node-1" || got.KekID != "instance-1" || got.KeyIdx != 7 || !got.KeyCreatedAt.Equal(testCreatedAt) {
		t.Errorf("request = %+v, want the node, instance, key-ring index and key stamp", got)
	}
	if resp.Command != model.TKFSCommandRekey {
		t.Errorf("response = %+v, want the command passed through", resp)
	}

	status = http.StatusForbidden
	if _, err := s.Heartbeat(0, testCreatedAt); !errors.Is(err, ErrDenied) {
		t.Errorf("403 error = %v, want one wrapping ErrDenied", err)
	}
	for _, code := range []int{http.StatusNotFound, http.StatusNotImplemented} {
		status = code
		_, err := s.Heartbeat(0, testCreatedAt)
		if !errors.Is(err, ErrNotImplemented) {
			t.Errorf("%d error = %v, want one wrapping ErrNotImplemented", code, err)
		}
		if errors.Is(err, ErrDenied) {
			t.Errorf("%d must not read as a denial: %v", code, err)
		}
	}
	status = http.StatusServiceUnavailable
	if _, err := s.Heartbeat(0, testCreatedAt); err == nil {
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
		if _, err := s.Heartbeat(0, testCreatedAt); err != nil {
			t.Fatalf("one host without the route failed the call: %v", err)
		}
	}
	s.kmsHosts = []string{"kms-old", "kms-old"}
	if _, err := s.Heartbeat(0, testCreatedAt); !errors.Is(err, ErrNotImplemented) {
		t.Errorf("every host 404 = %v, want ErrNotImplemented", err)
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
		_, err := s.Heartbeat(0, testCreatedAt)
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
		if _, err := s.Heartbeat(0, testCreatedAt); !CredentialsRejected(err) {
			t.Errorf("%q from the transport: CredentialsRejected = false", alert)
		}
	}
	s := newTestSearchConnector(func(*http.Request) (*http.Response, error) {
		return jsonResponse(http.StatusBadGateway, "dial upstream: remote error: tls: bad certificate"), nil
	})
	s.identity.adopt("instance-1")
	if _, err := s.Heartbeat(0, testCreatedAt); err == nil || CredentialsRejected(err) {
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
	if _, err := s.Heartbeat(0, testCreatedAt); err != nil {
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
