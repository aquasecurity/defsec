package eks

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

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
						PublicAccessEnabled: types.Bool(true, types.NewTestMetadata()),
						PublicAccessCIDRs: []types.StringValue{
							types.String("0.0.0.0/0", types.NewTestMetadata()),
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
						PublicAccessEnabled: types.Bool(true, types.NewTestMetadata()),
						PublicAccessCIDRs: []types.StringValue{
							types.String("10.2.0.0/8", types.NewTestMetadata()),
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
						PublicAccessEnabled: types.Bool(false, types.NewTestMetadata()),
						PublicAccessCIDRs: []types.StringValue{
							types.String("10.2.0.0/8", types.NewTestMetadata()),
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
