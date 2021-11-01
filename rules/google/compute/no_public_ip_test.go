package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/google/compute"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/defsec/types"
	"github.com/stretchr/testify/assert"
)

var fakeMetadata = types.NewMetadata(types.NewRange("main.tf", 124, 124), &types.FakeReference{})

func Test_No_Public_IP(t *testing.T) {
	var s state.State
	s.Google.Compute.Instances = []compute.Instance{
		{
			Metadata: fakeMetadata,
			NetworkInterfaces: []compute.NetworkInterface{
				{
					Metadata:    fakeMetadata,
					HasPublicIP: types.Bool(true, fakeMetadata),
				},
			},
		},
	}
	results := CheckInstancesDoNotHavePublicIPs.Evaluate(&s)
	assert.Len(t, results, 1)
}
