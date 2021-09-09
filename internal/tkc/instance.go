package tkc

import (
	"sync"
)

var (
	c        KMSConnector
	initOnce sync.Once
)

// Get retrieves the connection to the KMS
func Get() KMSConnector {
	initOnce.Do(func() {
		c = NewTKConnector(new(TKConfig))
		// c = NewTKConnector(&TKConfig{
		// 	NodeID:       "123",
		// 	TenantID:     "testing",
		// 	KMSPort:      7070,
		// 	KMSTrustPort: 7071,
		// 	KMSClusters: []kmsclient.KMSClusterInfo{
		// 		{
		// 			Hosts: []string{"10.85.250.100"},
		// 			Name:  "local",
		// 		},
		// 	},
		// })
	})
	return c
}
