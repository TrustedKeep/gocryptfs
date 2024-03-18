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
	"time"

	"github.com/TrustedKeep/tkutils/v2/diskutil"
	"github.com/TrustedKeep/tkutils/v2/kem"
	"github.com/TrustedKeep/tkutils/v2/kmsclient"
	"github.com/TrustedKeep/tkutils/v2/tlsutils"
)

var errNotImplemented = errors.New("not implemented in search connector")

var _ KMSConnector = (*searchConnector)(nil)

type searchConnector struct {
	currKeyID   string
	ramdiskPath string
	lastUpdate  time.Time
	client      *http.Client
	token       string
	kmsHosts    []string
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
	sc.lastUpdate = fi.ModTime()
	sc.token = string(tokenBytes)
	sc.kmsHosts = hosts
	sc.client = &http.Client{
		Timeout: time.Second * 10,
		Transport: &http.Transport{
			MaxIdleConns:    1,
			MaxConnsPerHost: 2,
			IdleConnTimeout: time.Minute,
			TLSClientConfig: tlsConfig,
		},
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
	return sc.currKeyID
}

func (sc *searchConnector) SetCurrentKeyID(id string) {
	sc.currKeyID = id
}

func (sc *searchConnector) fetchKey(keyID string) (newID string, key kem.Kem, lastErr error) {
	if len(keyID) == 0 {
		keyID = sc.currKeyID
	}

	doFetch := func(host string) (err error) {
		log.Printf("Fetching envelope key \"%s\" from KMS %s\n", keyID, host)
		var u string
		if len(keyID) > 0 {
			u = fmt.Sprintf("https://%s:7070/keepsvc/tenantek/retrieve/%s", host, keyID)
		} else {
			u = fmt.Sprintf("https://%s:7070/keepsvc/tenantek/current/%d", host, kem.RSA3072)
		}

		req, err := http.NewRequest(http.MethodGet, u, nil)
		if err != nil {
			return
		}
		req.Header.Set(kmsclient.HeaderTenantToken, sc.token)

		resp, err := sc.client.Do(req)
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

	for _, x := range rand.Perm(len(sc.kmsHosts)) {
		if lastErr = doFetch(sc.kmsHosts[x]); lastErr == nil {
			return
		}
	}
	return
}
