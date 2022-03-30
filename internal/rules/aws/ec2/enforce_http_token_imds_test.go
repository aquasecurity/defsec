package ec2

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckIMDSAccessRequiresToken(t *testing.T) {
	tests := []struct {
		name     string
		input    ec2.EC2
		expected bool
	}{
		{
			name: "positive result",
			input: ec2.EC2{
				Instances: []ec2.Instance{
					{
						Metadata: types.NewTestMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							Metadata:     types.NewTestMetadata(),
							HttpTokens:   types.String("optional", types.NewTestMetadata()),
							HttpEndpoint: types.String("enabled", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "negative result",
			input: ec2.EC2{
				Instances: []ec2.Instance{
					{
						Metadata: types.NewTestMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							Metadata:     types.NewTestMetadata(),
							HttpTokens:   types.String("required", types.NewTestMetadata()),
							HttpEndpoint: types.String("disabled", types.NewTestMetadata()),
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
			testState.AWS.EC2 = test.input
			results := CheckIMDSAccessRequiresToken.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckIMDSAccessRequiresToken.Rule().LongID() {
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
