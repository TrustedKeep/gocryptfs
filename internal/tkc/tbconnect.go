package tkc

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"fmt"

	client "github.com/TrustedKeep/boundary/client"
	"github.com/TrustedKeep/boundary/common"
	"github.com/TrustedKeep/boundary/tcmproto"
	"github.com/TrustedKeep/tkutils/v2/certutil"
	"github.com/TrustedKeep/tkutils/v2/kem"
	"github.com/google/uuid"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

var _ KMSConnector = &tbConnector{}

// tbConnector connects us to Boundary for key retrieval
type tbConnector struct {
	nodeID     string
	c          *client.Client
	publicKey  []byte
	privateKey *rsa.PrivateKey
}

// newtbConnector creates and initializes our connection to Boundary.  If we are
// unable to connect, this is a fatal error.
func newtbConnector(tbHost, id string, mockAWS bool) KMSConnector {
	tbc := &tbConnector{
		nodeID: id,
	}

	var ac client.AuthProvider
	if mockAWS {
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
			//TODO: This is where we'd check for a forced key rotation
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
func (tbc *tbConnector) GetKey(path []byte) (key []byte, err error) {
	path = bytes.Join([][]byte{[]byte(tbc.nodeID), path}, []byte("/"))

	tlog.Debug.Printf("Retrieving key from KMS: %s", string(path))
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

func (tbc *tbConnector) GetEnvelopeKey(id string) (key kem.Kem, err error) {
	//get kem
	tlog.Info.Printf("Retrieving envelope key from KMS: %s", string(id))
	var resp *tcmproto.RetrieveEKResponse
	if resp, err = tbc.c.Connection().RetrieveEK(context.Background(), &tcmproto.RetrieveEKRequest{
		Path: tbc.ekPath(id),
	}); err != nil {
		return
	}
	//unmarshal it
	return kem.UnmarshalKem(resp.EKBytes)
}

func (tbc *tbConnector) CreateEnvelopeKey(ktStr string) (id string, key kem.Kem, err error) {
	// create the new key
	id = uuid.NewString()
	var resp *tcmproto.CreateEKResponse
	if resp, err = tbc.c.Connection().CreateEK(context.Background(), &tcmproto.CreateEKRequest{
		Path: tbc.ekPath(id),
		Type: ktStr,
	}); err != nil {
		return
	}

	//unmarshal it
	key, err = kem.UnmarshalKem(resp.EKBytes)
	if err != nil {
		return
	}

	return
}

func (tbc *tbConnector) ekPath(id string) string {
	return fmt.Sprintf("%s/%s", tbc.nodeID, id)
}
