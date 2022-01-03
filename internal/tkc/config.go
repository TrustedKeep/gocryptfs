package tkc

import (
	"encoding/hex"
	"fmt"
	"hash/fnv"
	"io/ioutil"

	"github.com/TrustedKeep/tkutils/v2/network"
	"github.com/TrustedKeep/tkutils/v2/stringutil"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
	yaml "gopkg.in/yaml.v2"
)

// TKConfig represents the configuration values needed to connect to TK
type TKConfig struct {
	NodeID        string `yaml:"NodeID"`
	TenantID      string `yaml:"TenantID"`
	BoundaryHost  string `yaml:"BoundaryHost"`
	MockConnector bool   `yaml:"MockConnector"`
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
	if stringutil.Empty(cfg.NodeID) {
		fh := fnv.New32a()
		fh.Write([]byte(network.GetLocalIP()))
		cfg.NodeID = fmt.Sprintf("tkfs-%s", hex.EncodeToString(fh.Sum(nil)))
		tlog.Info.Printf("No node ID specified, generated default ID: %s", cfg.NodeID)
	}
	if len(cfg.BoundaryHost) == 0 {
		cfg.BoundaryHost = network.GetLocalIP()
	}

	return &cfg
}
