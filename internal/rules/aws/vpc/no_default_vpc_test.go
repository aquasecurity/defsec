package vpc

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/vpc"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoDefaultVpc(t *testing.T) {
	tests := []struct {
		name     string
		input    vpc.VPC
		expected bool
	}{
		{
			name: "default AWS VPC",
			input: vpc.VPC{
				DefaultVPCs: []vpc.DefaultVPC{
					{
						Metadata: types.NewTestMetadata(),
					},
				},
			},
			expected: true,
		},
		{
			name:     "no default AWS VPC",
			input:    vpc.VPC{},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.VPC = test.input
			results := CheckNoDefaultVpc.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoDefaultVpc.Rule().LongID() {
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
