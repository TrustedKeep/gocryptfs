package tkc

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/TrustedKeep/tkutils/v2/awsidentity"
	"github.com/TrustedKeep/tkutils/v2/model"
)

// The lookup runs once, on first use, and its answer is kept whether it succeeded or not: the document never
// changes on a machine, and off EC2 each lookup costs its timeout.
func TestMachineIdentityIsFetchedOnce(t *testing.T) {
	for _, fail := range []bool{false, true} {
		calls := 0
		m := onceMachineIdentity(func(ctx context.Context) (*model.TKFSIdentityProof, error) {
			calls++
			if d, ok := ctx.Deadline(); !ok || time.Until(d) > machineFetchTimeout {
				t.Errorf("fail=%v: the lookup is not bounded by %v", fail, machineFetchTimeout)
			}
			if fail {
				return nil, errors.New("no IMDS here")
			}
			return awsidentity.Mock(), nil
		})
		if calls != 0 {
			t.Fatalf("fail=%v: fetched before first use", fail)
		}
		first, second := m(), m()
		if calls != 1 {
			t.Errorf("fail=%v: fetched %d times, want once", fail, calls)
		}
		if first != second || (first == nil) != fail {
			t.Errorf("fail=%v: proofs = %p, %p", fail, first, second)
		}
	}
}

// The proof must ride every call, since the gateway verifies it on each one.
func TestGatewayConnectorProvesItsMachine(t *testing.T) {
	var gen model.TKFSDataKeyGenerateRequest
	var unw model.TKFSDataKeyUnwrapRequest
	var hb model.TKFSHeartbeatRequest
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case gatewayGeneratePath:
			_ = json.NewDecoder(r.Body).Decode(&gen)
		case gatewayUnwrapPath:
			_ = json.NewDecoder(r.Body).Decode(&unw)
		case gatewayHeartbeatPath:
			_ = json.NewDecoder(r.Body).Decode(&hb)
		}
		http.Error(w, "enough", http.StatusInternalServerError)
	}))
	defer ts.Close()

	g := newTestGWConnector(ts, "node-1")
	g.machine = newMachineIdentity(true)
	g.identity.adopt("instance-1")
	_, _ = g.GenerateTKFSDataKey()
	_, _ = g.UnwrapTKFSDataKey("instance-1", []byte("c"))
	_, _ = g.Heartbeat(0, testCreatedAt)

	want := awsidentity.Mock()
	for name, got := range map[string]*model.TKFSIdentityProof{"generate": gen.Identity, "unwrap": unw.Identity, "heartbeat": hb.Identity} {
		if !reflect.DeepEqual(got, want) {
			t.Errorf("%s Identity = %+v, want the mock proof", name, got)
		}
	}
}

// writeCertDir writes a self-signed client cert, its key and itself as the CA, as -gateway-cert-dir holds.
func writeCertDir(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "tkfs-test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour), IsCA: true, BasicConstraintsValid: true}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	dir := t.TempDir()
	for name, data := range map[string][]byte{
		gatewayCertFile: certPEM,
		gatewayKeyFile:  pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		gatewayCAFile:   certPEM,
	} {
		if err := os.WriteFile(filepath.Join(dir, name), data, 0600); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// The gateway connector gets its machine identity at construction: the mock with -mock-aws, an IMDS
// lookup otherwise.
func TestGatewayConnectorIsBuiltWithItsMachine(t *testing.T) {
	g := newGatewayConnector("gateway:7083", writeCertDir(t), "node-1", true, false)
	if !reflect.DeepEqual(g.machine(), awsidentity.Mock()) {
		t.Error("-mock-aws did not reach the gateway connector")
	}
	m := newGatewayConnector("gateway:7083", writeCertDir(t), "node-1", false, false).machine
	if m == nil || reflect.ValueOf(m).Pointer() == reflect.ValueOf(awsidentity.Mock).Pointer() {
		t.Error("without -mock-aws the gateway connector does not read IMDS")
	}
}

// The gateway connector reports -sharedstorage on every call: a gateway requiring binding must refuse
// the mount wherever it is first asked.
func TestGatewayConnectorReportsSharedStorage(t *testing.T) {
	sent := map[string]bool{}
	record := func(path string, body []byte) {
		var req struct{ SharedStorage bool }
		_ = json.Unmarshal(body, &req)
		sent[path] = req.SharedStorage
	}
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		record(r.URL.Path, b)
		http.Error(w, "enough", http.StatusInternalServerError)
	}))
	defer ts.Close()
	for _, want := range []bool{false, true} {
		clear(sent)
		g := newTestGWConnector(ts, "node-1")
		g.sharedStorage = want
		g.identity.adopt("instance-1")
		_, _ = g.GenerateTKFSDataKey()
		_, _ = g.UnwrapTKFSDataKey("instance-1", []byte("c"))
		_, _ = g.Heartbeat(0, testCreatedAt)

		for _, path := range []string{gatewayGeneratePath, gatewayUnwrapPath, gatewayHeartbeatPath} {
			if got, ok := sent[path]; !ok || got != want {
				t.Errorf("sharedStorage=%v: %s reported SharedStorage=%v", want, path, got)
			}
		}
		if got := newGatewayConnector("gateway:7083", writeCertDir(t), "node-1", false, want).sharedStorage; got != want {
			t.Errorf("-sharedstorage=%v reached the gateway connector as %v", want, got)
		}
	}
}
