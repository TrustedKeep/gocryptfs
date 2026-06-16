package tkc

import (
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"go/build"
	"io"
	"log"
	"math/rand"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/TrustedKeep/tkutils/v2/diskutil"
	"github.com/TrustedKeep/tkutils/v2/kem"
	"github.com/TrustedKeep/tkutils/v2/kmsclient"
	"github.com/TrustedKeep/tkutils/v2/tlsutils"
)

var errNotImplemented = errors.New("not implemented in search connector")

var _ KMSConnector = (*searchConnector)(nil)

type searchConnector struct {
	// mu guards the fields below that newClient/SetCurrentKeyID swap out while fetchKey
	// reads them concurrently (gocryptfs calls in on FS ops). Without it a torn slice/
	// string read could panic.
	mu          sync.RWMutex
	currKeyID   string
	ramdiskPath string
	lastUpdate  time.Time
	client      *http.Client
	token       string
	kmsHosts    []string
	nexus       bool // additive: fetch keys from Nexus's Search endpoint instead of keep
}

func newSearchConnector() KMSConnector {
	s := &searchConnector{
		ramdiskPath: "/usr/local/trustedsearch/ramdisk",
	}
	if _, err := os.Stat(s.ramdiskPath); err != nil {
		if goPath := build.Default.GOPATH; len(goPath) > 0 {
			s.ramdiskPath = fmt.Sprintf("%s/src/github.com/TrustedKeep/lizard/local/ramdisk", goPath)
			diskutil.EnsureDir(s.ramdiskPath)
		}
	}
	s.newClient()
	go func() {
		for {
			<-time.After(time.Minute)
			s.newClient()
		}
	}()
	return s
}

func (sc *searchConnector) newClient() {
	certPath := fmt.Sprintf("%s/gw.cert.pem", sc.ramdiskPath)
	fi, err := os.Stat(certPath)
	if err != nil {
		log.Printf("error in stat on ramdisk cert : %v\n", err)
		return
	}
	if !fi.ModTime().After(sc.lastUpdate) {
		return
	}

	var hostsData []byte
	if hostsData, err = os.ReadFile(fmt.Sprintf("%s/gw.hosts.json", sc.ramdiskPath)); err != nil {
		log.Printf("error reading hosts data file: %v\n", err)
		return
	}
	var hosts []string
	if err = json.Unmarshal(hostsData, &hosts); err != nil {
		log.Printf("error unmarshaling hosts data: %v\n", err)
		return
	}
	if len(hosts) == 0 {
		log.Printf("empty hosts configuration\n")
		return
	}

	log.Printf("updating key retrieval certificate, last mod %s\n", fi.ModTime().String())
	var keyPEM, certPEM, caPEM []byte
	if certPEM, err = os.ReadFile(certPath); err != nil {
		log.Printf("error reading cert from ramdisk: %v\n", err)
		return
	}
	if keyPEM, err = os.ReadFile(fmt.Sprintf("%s/gw.key.pem", sc.ramdiskPath)); err != nil {
		log.Printf("error reading key from ramdisk: %v\n", err)
		return
	}
	if caPEM, err = os.ReadFile(fmt.Sprintf("%s/gw.ca.pem", sc.ramdiskPath)); err != nil {
		log.Printf("error reading ca from ramdisk:  %v\n", err)
		return
	}
	var tokenBytes []byte
	if tokenBytes, err = os.ReadFile(fmt.Sprintf("%s/gw.token", sc.ramdiskPath)); err != nil {
		log.Printf("error reading token from ramdisk: %v\n", err)
		return
	}
	var tlsConfig *tls.Config
	if tlsConfig, err = tlsutils.NewTLSConfigWithCert(keyPEM, certPEM, caPEM); err != nil {
		log.Printf("error building TLS configuration: %v\n", err)
		return
	}
	// Additive: a "nexus" provider marker on the ramdisk switches key retrieval to
	// Nexus's Search envelope-key endpoint. Absent (or any other value) preserves the
	// keep key-provider protocol, so existing tkfs/keep deployments are unaffected.
	nexusMode := false
	if modeBytes, merr := os.ReadFile(fmt.Sprintf("%s/gw.provider", sc.ramdiskPath)); merr == nil {
		nexusMode = parseProvider(modeBytes)
	}
	httpClient := &http.Client{
		Timeout: time.Second * 10,
		Transport: &http.Transport{
			MaxIdleConns:    1,
			MaxConnsPerHost: 2,
			IdleConnTimeout: time.Minute,
			TLSClientConfig: tlsConfig,
		},
	}
	sc.setState(httpClient, string(tokenBytes), hosts, nexusMode, fi.ModTime())
}

// parseProvider reports whether the ramdisk provider marker selects Nexus mode. Only an
// exact (whitespace-trimmed) "nexus" enables it; anything else keeps the keep protocol.
func parseProvider(b []byte) bool {
	return strings.TrimSpace(string(b)) == "nexus"
}

// setState atomically swaps the fields fetchKey reads, so a concurrent reader never sees
// a torn slice/string while newClient refreshes them on cert rotation.
func (sc *searchConnector) setState(client *http.Client, token string, hosts []string, nexus bool, modTime time.Time) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.client = client
	sc.token = token
	sc.kmsHosts = hosts
	sc.nexus = nexus
	sc.lastUpdate = modTime
}

// snapshot returns a consistent copy of the fields needed to fetch a key.
func (sc *searchConnector) snapshot() (client *http.Client, token string, nexus bool, hosts []string) {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.client, sc.token, sc.nexus, sc.kmsHosts
}

// keyURL builds the envelope-key retrieval URL for the active provider. Nexus mode uses
// the Search module's REST endpoint (the host already carries the port); keep mode uses
// the tenantek path on :7070.
func keyURL(nexus bool, host, keyID string) string {
	switch {
	case nexus && len(keyID) > 0:
		return fmt.Sprintf("https://%s/envelopekey/%s", host, keyID)
	case nexus:
		return fmt.Sprintf("https://%s/envelopekey/current", host)
	case len(keyID) > 0:
		return fmt.Sprintf("https://%s:7070/keepsvc/tenantek/retrieve/%s", host, keyID)
	default:
		return fmt.Sprintf("https://%s:7070/keepsvc/tenantek/current/%d", host, kem.RSA3072)
	}
}

func (sc *searchConnector) GetKey(path []byte) ([]byte, error) {
	return nil, errNotImplemented
}

func (sc *searchConnector) GetEnvelopeKey(id string) (key kem.Kem, err error) {
	_, key, err = sc.fetchKey(id)
	return
}

func (sc *searchConnector) CreateEnvelopeKey(ktStr string, name string) (id string, key kem.Kem, err error) {
	return sc.fetchKey("")
}

func (sc *searchConnector) GetCurrentKeyID() string {
	sc.mu.RLock()
	defer sc.mu.RUnlock()
	return sc.currKeyID
}

func (sc *searchConnector) SetCurrentKeyID(id string) {
	sc.mu.Lock()
	defer sc.mu.Unlock()
	sc.currKeyID = id
}

func (sc *searchConnector) fetchKey(keyID string) (newID string, key kem.Kem, lastErr error) {
	if len(keyID) == 0 {
		keyID = sc.GetCurrentKeyID()
	}
	// Snapshot the shared state (newClient swaps it wholesale on cert refresh) so the
	// network calls below operate on a consistent copy.
	client, token, nexus, hosts := sc.snapshot()

	doFetch := func(host string) (err error) {
		log.Printf("Fetching envelope key \"%s\" from %s\n", keyID, host)
		u := keyURL(nexus, host, keyID)

		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return
		}
		req.Header.Set(kmsclient.HeaderTenantToken, token)

		resp, err := client.Do(req)
		if err != nil {
			return
		}
		body, _ := io.ReadAll(resp.Body)
		resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("error retrieving envelope key, server returned %d (%s)", resp.StatusCode, body)
			return
		}

		if key, err = kem.UnmarshalKem(body); err != nil {
			return
		}

		if newID = resp.Header.Get("x-tk-kem-id"); len(newID) == 0 {
			newID = keyID
		}

		log.Printf("Fetched key \"%s\" from KMS", newID)
		return
	}

	for _, x := range rand.Perm(len(hosts)) {
		if lastErr = doFetch(hosts[x]); lastErr == nil {
			return
		}
	}
	return
}
