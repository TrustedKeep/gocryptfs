package tkc

import (
	"bytes"
	"context"
	cryptrand "crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"math/rand"
	"sync"
	"time"

	"github.com/TrustedKeep/tkutils/v2/certutil"
	"github.com/TrustedKeep/tkutils/v2/kmsclient"
	client "github.com/TrustedKeep/tkutils/v2/kmsclient"
	"github.com/TrustedKeep/tkutils/v2/licensing"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
	"google.golang.org/grpc/connectivity"
	"google.golang.org/grpc/metadata"
)

func init() {
	rand.Seed(time.Now().Unix())
}

const (
	headerToken   = "X-TrustedKMS-Token"
	headerTenant  = "X-TrustedKMS-TenantID"
	headerActorDN = "X-TrustedKMS-ActorDN"
)

// KMSConnector connects the encryptor to a KMS
type KMSConnector interface {
	Start() error
	Ready() chan struct{}
	GetKey(path []byte) (key []byte, err error)
}

var _ KMSConnector = &TKConnector{}

// TKConnector is responsible for connecting to TrustedKeep for key management
type TKConnector struct {
	ready      chan struct{}
	startOnce  sync.Once
	grpcClient *client.PeerClient
	kc         *client.HAKeepClient
	connMu     sync.Mutex
	tenantID   string
	nodeID     string
	publicKey  []byte
	privateKey *rsa.PrivateKey
}

// NewTKConnector constructs a new TrustedKeep connector
func NewTKConnector(cfg *TKConfig) KMSConnector {
	if len(cfg.KMSClusters) == 0 {
		return newMockConnector()
	}

	c := &TKConnector{
		ready:    make(chan struct{}),
		tenantID: cfg.TenantID,
		nodeID:   cfg.NodeID,
		kc: kmsclient.NewHAKeepClient(&kmsclient.Config{
			ManagementPort:   cfg.KMSPort,
			TrustPort:        cfg.KMSTrustPort,
			TenantID:         cfg.TenantID,
			InstanceID:       cfg.NodeID,
			Features:         licensing.FeatureTKFS,
			Version:          "v0.0",
			FailureTolerance: cfg.FailureTolerance,
			RequestSigner:    cfg.GetSigner(),
		}, cfg.KMSClusters),
	}
	prvKey, err := certutil.GeneratePrivateKey(certutil.KeyTypeRSA)
	if err != nil {
		panic(err)
	}
	c.privateKey = prvKey.(*rsa.PrivateKey)
	c.publicKey, _ = x509.MarshalPKIXPublicKey(&c.privateKey.PublicKey)
	return c
}

// Start opens connections to TK and starts cert request process
func (c *TKConnector) Start() (err error) {
	c.startOnce.Do(func() {
		go func() {
			<-c.kc.Ready()
			close(c.ready)
		}()
	})
	return
}

// Ready is the chan that will close when it's initialized and ready to go
func (c *TKConnector) Ready() chan struct{} {
	return c.ready
}

// GetKey from KMS
func (c *TKConnector) GetKey(path []byte) ([]byte, error) {
	// TODO: formalize this, constants and such.  set c.nodeID on init
	path = bytes.Join([][]byte{[]byte(c.nodeID), path}, []byte("/"))

	tlog.Debug.Printf("Retrieving key from KMS")
	gClient := c.getClient()
	if gClient == nil {
		return nil, errors.New("No KMS connection available")
	}
	req := &client.GetKeyRequest{
		Path:      path,
		PublicKey: c.publicKey,
	}
	kp := c.kc.Get().GetKeyPair()
	ctx := metadata.AppendToOutgoingContext(context.Background(),
		headerToken,
		kp.Token,
		headerActorDN,
		kp.Certificate.Subject.String(),
		headerTenant,
		c.tenantID,
	)
	resp, err := gClient.RSAGetKey(ctx, req)
	if err != nil {
		tlog.Warn.Printf("Error retrieving key from KMS: %v", err)
		return nil, err
	}
	var decryptedKey []byte
	if decryptedKey, err = rsa.DecryptOAEP(sha256.New(), cryptrand.Reader, c.privateKey, resp.Key, nil); err != nil {
		return nil, err
	}
	return decryptedKey, nil
}

func (c *TKConnector) getClient() client.KMSServiceClient {
	c.connMu.Lock()
	defer c.connMu.Unlock()

	connected := c.grpcClient != nil && c.grpcClient.IsOpen()
	for !connected {
		cfg := c.kc.ActiveConfig()
		kp := c.kc.Get().GetKeyPair()
		kpKey, _ := certutil.EncodePrivateKey(certutil.EncodingPKCS8, kp.Key)
		hosts := append([]string{}, cfg.Hosts...)
		rand.Shuffle(len(hosts), func(i, j int) {
			tmp := hosts[i]
			hosts[i] = hosts[j]
			hosts[j] = tmp
		})
		for x := 0; x < len(hosts); x++ {
			tlog.Info.Printf("Attempting to connect to KMS %s:%s", cfg.Name, hosts[x])
			pcConfig := client.PeerConfig{
				ClientCertificate: certutil.EncodeCertificate(kp.Certificate),
				ClientKey:         kpKey,
				RootCAs:           kp.TrustChain,
			}
			ctx, done := context.WithTimeout(context.Background(), time.Second*3)
			pc := client.NewPeerClient(pcConfig, hosts[x])
			if err := pc.OpenContext(ctx); err != nil {
				done()
				tlog.Warn.Printf("Error opening KMS connection: %v", err)
				continue
			}
			done()
			c.grpcClient = pc
			go func(tmpClient *client.PeerClient, clusterName string) {
				tmpClient.GetConn().WaitForStateChange(context.Background(), connectivity.Ready)
				tlog.Warn.Printf("Lost connection to KMS %s", clusterName)
				tmpClient.Close()
			}(pc, cfg.Name)
			connected = true
			break
		}
		if !connected {
			tlog.Warn.Printf("Unable to connect to any KMS hosts in cluster %s", cfg.Name)
			<-time.After(time.Second * 5)
		}
	}
	return client.NewKMSServiceClient(c.grpcClient.GetConn())
}
