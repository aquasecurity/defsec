package ec2

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestASCheckIMDSAccessRequiresToken(t *testing.T) {
	tests := []struct {
		name     string
		input    ec2.EC2
		expected bool
	}{
		{
			name: "Launch configuration with optional tokens",
			input: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							Metadata:     defsecTypes.NewTestMetadata(),
							HttpTokens:   defsecTypes.String("optional", defsecTypes.NewTestMetadata()),
							HttpEndpoint: defsecTypes.String("enabled", defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Launch template with optional tokens",
			input: ec2.EC2{
				LaunchTemplates: []ec2.LaunchTemplate{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Instance: ec2.Instance{
							Metadata: defsecTypes.NewTestMetadata(),
							MetadataOptions: ec2.MetadataOptions{
								Metadata:     defsecTypes.NewTestMetadata(),
								HttpTokens:   defsecTypes.String("optional", defsecTypes.NewTestMetadata()),
								HttpEndpoint: defsecTypes.String("enabled", defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Launch configuration with required tokens",
			input: ec2.EC2{
				LaunchConfigurations: []ec2.LaunchConfiguration{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							Metadata:     defsecTypes.NewTestMetadata(),
							HttpTokens:   defsecTypes.String("required", defsecTypes.NewTestMetadata()),
							HttpEndpoint: defsecTypes.String("enabled", defsecTypes.NewTestMetadata()),
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
			results := CheckASIMDSAccessRequiresToken.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckASIMDSAccessRequiresToken.Rule().LongID() {
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
