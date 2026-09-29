package tkc

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

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
// same pass-through of a shutdown directive, and the same three failure classes. 403 is revocation,
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

	resp, err := s.Heartbeat(7)
	if err != nil {
		t.Fatalf("Heartbeat: %v", err)
	}
	if got.NodeID != "node-1" || got.InstanceID != "instance-1" || got.KeyIdx != 7 {
		t.Errorf("request = %+v, want the node, instance and key-ring index", got)
	}
	if resp.Command != model.TKFSCommandRekey {
		t.Errorf("response = %+v, want the command passed through", resp)
	}

	status = http.StatusForbidden
	if _, err := s.Heartbeat(0); !errors.Is(err, ErrDenied) {
		t.Errorf("403 error = %v, want one wrapping ErrDenied", err)
	}
	for _, code := range []int{http.StatusNotFound, http.StatusNotImplemented} {
		status = code
		_, err := s.Heartbeat(0)
		if !errors.Is(err, ErrNotImplemented) {
			t.Errorf("%d error = %v, want one wrapping ErrNotImplemented", code, err)
		}
		if errors.Is(err, ErrDenied) {
			t.Errorf("%d must not read as a denial: %v", code, err)
		}
	}
	status = http.StatusServiceUnavailable
	if _, err := s.Heartbeat(0); err == nil {
		t.Error("503 must be an error")
	} else if errors.Is(err, ErrDenied) || errors.Is(err, ErrNotImplemented) {
		t.Errorf("503 must read as a plain outage: %v", err)
	}
}

// The tenant token authenticates the call alongside the mTLS cert, so every route has to carry it.
func TestSearchConnectorSendsTenantToken(t *testing.T) {
	var token string
	s := newTestSearchConnector(func(r *http.Request) (*http.Response, error) {
		token = r.Header.Get(kmsclient.HeaderTenantToken)
		return jsonResponse(http.StatusOK, model.TKFSHeartbeatResponse{}), nil
	})
	if _, err := s.Heartbeat(0); err != nil {
		t.Fatal(err)
	}
	if token != "tenant-token" {
		t.Errorf("token header = %q, want the connector's token", token)
	}
}
