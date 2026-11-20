package tkc

import (
	"context"
	"sync"
	"time"

	"github.com/TrustedKeep/tkutils/v2/awsidentity"
	"github.com/TrustedKeep/tkutils/v2/model"
	"github.com/rfjakob/gocryptfs/v2/internal/tlog"
)

// machineFetchTimeout bounds one IMDS lookup, the SDK's retries included. A container behind a hop limit of
// 1 falls back to IMDSv1 in about 3.5 seconds; off EC2 a lookup is refused in about 4, or runs into this bound
// where packets are dropped.
const machineFetchTimeout = 5 * time.Second

// machineIdentity returns the RSA-2048 signed instance-identity document that proves which machine this
// mount runs on, or nil when there is none, in which case a gateway that requires binding refuses the call.
type machineIdentity func() *model.TKFSIdentityProof

// newMachineIdentity reads the document from EC2 IMDS, or with mockAWS uses tkutils' test-signed mock.
func newMachineIdentity(mockAWS bool) machineIdentity {
	if mockAWS {
		return awsidentity.Mock
	}
	return onceMachineIdentity(awsidentity.Fetch)
}

// onceMachineIdentity looks the document up on first use and keeps the answer, success or failure, for the
// mount's life: the SDK already retries within the lookup, and off EC2 each one costs its timeout.
func onceMachineIdentity(fetch func(context.Context) (*model.TKFSIdentityProof, error)) machineIdentity {
	return sync.OnceValue(func() *model.TKFSIdentityProof {
		ctx, cancel := context.WithTimeout(context.Background(), machineFetchTimeout)
		defer cancel()
		p, err := fetch(ctx)
		if err != nil {
			tlog.Warn.Printf("No instance-identity document (%v); a gateway that requires instance binding will refuse this mount", err)
			return nil
		}
		return p
	})
}
