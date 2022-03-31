package autoscaling

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/autoscaling"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoSensitiveInfo(t *testing.T) {
	tests := []struct {
		name     string
		input    autoscaling.Autoscaling
		expected bool
	}{
		{
			name: "Launch configuration with sensitive info in user data",
			input: autoscaling.Autoscaling{
				LaunchConfigurations: []autoscaling.LaunchConfiguration{
					{
						Metadata: types.NewTestMetadata(),
						UserData: types.String(`
						export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
						export AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY
						export AWS_DEFAULT_REGION=us-west-2
						`, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Launch configuration with no sensitive info in user data",
			input: autoscaling.Autoscaling{
				LaunchConfigurations: []autoscaling.LaunchConfiguration{
					{
						Metadata: types.NewTestMetadata(),
						UserData: types.String(`
						export GREETING=hello
						`, types.NewTestMetadata()),
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
			results := CheckNoSensitiveInfo.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoSensitiveInfo.Rule().LongID() {
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
