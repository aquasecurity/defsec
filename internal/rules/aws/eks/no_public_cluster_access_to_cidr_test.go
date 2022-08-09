package eks

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/eks"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicClusterAccessToCidr(t *testing.T) {
	tests := []struct {
		name     string
		input    eks.EKS
		expected bool
	}{
		{
			name: "EKS Cluster with public access CIDRs actively set to open",
			input: eks.EKS{
				Clusters: []eks.Cluster{
					{
						PublicAccessEnabled: types2.Bool(true, types2.NewTestMetadata()),
						PublicAccessCIDRs: []types2.StringValue{
							types2.String("0.0.0.0/0", types2.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "EKS Cluster with public access enabled but private CIDRs",
			input: eks.EKS{
				Clusters: []eks.Cluster{
					{
						PublicAccessEnabled: types2.Bool(true, types2.NewTestMetadata()),
						PublicAccessCIDRs: []types2.StringValue{
							types2.String("10.2.0.0/8", types2.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "EKS Cluster with public access disabled and private CIDRs",
			input: eks.EKS{
				Clusters: []eks.Cluster{
					{
						PublicAccessEnabled: types2.Bool(false, types2.NewTestMetadata()),
						PublicAccessCIDRs: []types2.StringValue{
							types2.String("10.2.0.0/8", types2.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.EKS = test.input
			results := CheckNoPublicClusterAccessToCidr.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicClusterAccessToCidr.Rule().LongID() {
					found = true
				}
			}
			if test.expected {
				assert.True(t, found, "Rule should have been found")
			} else {
				assert.False(t, found, "Rule should not have been found")
			}
		})
	}
}
