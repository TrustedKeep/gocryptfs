package tkc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"

	client "github.com/TrustedKeep/boundary/client"
	"github.com/TrustedKeep/boundary/common"
	"github.com/TrustedKeep/boundary/tcmproto"
	"github.com/TrustedKeep/tkutils/v2/certutil"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// TBConnector connects us to Boundary for key retrieval
type TBConnector struct {
	nodeID     string
	c          *client.Client
	publicKey  []byte
	privateKey *rsa.PrivateKey
}

// NewTBConnector creates and initializes our connection to Boundary.  If we are
// unable to connect, this is a fatal error
func NewTBConnector(tbHost, id string, useMock bool) KMSConnector {
	tbc := &TBConnector{
		nodeID: id,
	}

	var ac client.AuthProvider
	if useMock {
		ac = client.NewMockAWSAuthProvider()
	} else {
		ac = client.NewAWSAuthProvider("")
	}

	var err error
	if tbc.c, err = client.NewClient(common.TKFS, tbHost, ac); err != nil {
		tlog.Fatal.Printf("Unable to connect to TrustedBoundary: %v\n", err)
	}
	go func() {
		for {
			// ignore hearbeats
			<-tbc.c.Heartbeat()
		}
	}()
	prvKey, err := certutil.GeneratePrivateKey(certutil.KeyTypeRSA)
	if err != nil {
		panic(err)
	}
	tbc.privateKey = prvKey.(*rsa.PrivateKey)
	tbc.publicKey, _ = x509.MarshalPKIXPublicKey(&tbc.privateKey.PublicKey)
	return tbc
}

// GetKey from KMS
func (tbc *TBConnector) GetKey(path []byte) (key []byte, err error) {
	path = bytes.Join([][]byte{[]byte(tbc.nodeID), path}, []byte("/"))

	tlog.Debug.Printf("Retrieving key from KMS")
	var resp *tcmproto.GetKeyResponse
	if resp, err = tbc.c.Connection().GetKeyRSA(context.Background(), &tcmproto.GetKeyRequest{
		Path:      path,
		PublicKey: tbc.publicKey,
	}); err != nil {
		return
	}
	key, err = rsa.DecryptOAEP(sha256.New(), rand.Reader, tbc.privateKey, resp.Key, nil)
	return
}
