package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/definition"
	"github.com/aquasecurity/defsec/provider/google/compute"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func Test_No_Public_IP(t *testing.T) {
	var s state.State
	fakeMetadata := definition.NewMetadata(
		definition.NewRange("main.tf", 123, 123),
		&definition.FakeReference{},
	)
	s.Google.Compute.Instances = []compute.Instance{
		{
			Metadata: fakeMetadata,
			NetworkInterfaces: []compute.NetworkInterface{
				{
					Metadata:    fakeMetadata,
					HasPublicIP: definition.Bool(true, definition.NewRange("main.tf", 124, 124), &definition.FakeReference{}),
				},
			},
		},
	}
	results := CheckInstancesDoNotHavePublicIPs.Evaluate(&s)
	assert.Len(t, results, 1)
}
