package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/google/compute"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/defsec/testutil"
	"github.com/stretchr/testify/assert"
)

func Test_No_Public_IP(t *testing.T) {
	var s state.State
	s.Google.Compute.Instances = []compute.Instance{
		{
			NetworkInterfaces: []compute.NetworkInterface{
				{
					HasPublicIP: testutil.NewBoolValue(true),
				},
			},
		},
	}
	results := CheckInstancesDoNotHavePublicIPs.CheckFunc(&s)
	assert.Len(t, results, 1)
}
