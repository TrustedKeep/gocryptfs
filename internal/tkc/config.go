package tkc

import (
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"io/ioutil"
	"net"
	"net/url"
	"strings"

	"github.com/TrustedKeep/tkutils/v2/kmsclient"
	"github.com/TrustedKeep/tkutils/v2/network"
	"github.com/TrustedKeep/tkutils/v2/stringutil"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
	yaml "gopkg.in/yaml.v2"
)

// TKConfig represents the configuration values needed to connect to TK
type TKConfig struct {
	NodeID           string                     `yaml:"NodeID"`
	TenantID         string                     `yaml:"TenantID"`
	KMSPort          int                        `yaml:"KMSPort"`
	KMSTrustPort     int                        `yaml:"KMSTrustPort"`
	KMSClusters      []kmsclient.KMSClusterInfo `yaml:"KMSClusters"`
	FailureTolerance int                        `yaml:"FailureTolerance"`
	SignerPath       string                     `yaml:"SignerPath"`
	SignerInsecure   bool                       `yaml:"SignerInsecure"`
}

// ReadConfig will create the configuration by reading the specified file.  It will
// setup any defaults and verify that the configuration is valid.
func ReadConfig(fileName string) *TKConfig {
	var cfg TKConfig
	data, err := ioutil.ReadFile(fileName)
	if err != nil {
		panic(err)
	}
	if err = yaml.Unmarshal(data, &cfg); err != nil {
		panic(err)
	}
	if cfg.KMSPort == 0 {
		cfg.KMSPort = 7070
	}
	if cfg.KMSTrustPort == 0 {
		cfg.KMSTrustPort = 7071
	}
	var ipList []*net.IPAddr

	if ipList, err = network.GetPrivateIPv4(); err != nil {
		panic(err)
	}
	if len(ipList) == 0 {
		panic("Unable to find local IP address")
	}
	if stringutil.Empty(cfg.NodeID) {
		fh := fnv.New32a()
		fh.Write([]byte(network.GetLocalIP()))
		cfg.NodeID = fmt.Sprintf("tkfs-%s", hex.EncodeToString(fh.Sum(nil)))
		tlog.Info.Printf("No node ID specified, generated default ID: %s", cfg.NodeID)
	}
	if len(cfg.KMSClusters) == 1 {
		if cfg.KMSClusters[0].Name == "mockkms" {
			cfg.KMSClusters = nil
		} else if cfg.KMSClusters[0].Name == "localhost" {
			cfg.KMSClusters[0].Hosts = []string{network.GetLocalIP()}
		}
	}
	if len(cfg.SignerPath) > 0 {
		if strings.HasPrefix(cfg.SignerPath, "http") {
			if _, err := url.Parse(cfg.SignerPath); err != nil {
				tlog.Fatal.Printf("Invalid SignerPath URL : %v", err)
			}
		} else {
			data, err := ioutil.ReadFile(cfg.SignerPath)
			if err != nil {
				tlog.Fatal.Printf("Unable to read signing cert : %v", err)
			}
			if _, err = kmsclient.NewFileSigner(data); err != nil {
				tlog.Fatal.Printf("Invalid signer certificate : %v", err)
			}
		}
	}

	return &cfg
}

// GetSigner returns a configured signer for auto-approval, or nil if none configured
func (c *TKConfig) GetSigner() kmsclient.Signer {
	if len(c.SignerPath) > 0 {
		if strings.HasPrefix(c.SignerPath, "http") {
			u, _ := url.Parse(c.SignerPath)
			return kmsclient.NewRemoteSigner(u, c.SignerInsecure)
		}
		data, _ := ioutil.ReadFile(c.SignerPath)
		fs, _ := kmsclient.NewFileSigner(data)
		return fs
	}
	return nil
}
