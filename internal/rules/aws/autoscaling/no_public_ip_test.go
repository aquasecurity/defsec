package autoscaling

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/autoscaling"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicIp(t *testing.T) {
	tests := []struct {
		name     string
		input    autoscaling.Autoscaling
		expected bool
	}{
		{
			name: "Launch configuration with public access",
			input: autoscaling.Autoscaling{
				LaunchConfigurations: []autoscaling.LaunchConfiguration{
					{
						Metadata:          types.NewTestMetadata(),
						AssociatePublicIP: types.Bool(true, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Launch configuration without public access",
			input: autoscaling.Autoscaling{
				LaunchConfigurations: []autoscaling.LaunchConfiguration{
					{
						Metadata:          types.NewTestMetadata(),
						AssociatePublicIP: types.Bool(false, types.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.Autoscaling = test.input
			results := CheckNoPublicIp.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicIp.Rule().LongID() {
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
