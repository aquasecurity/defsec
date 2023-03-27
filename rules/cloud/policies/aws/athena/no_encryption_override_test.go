package athena

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/athena"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoEncryptionOverride(t *testing.T) {
	tests := []struct {
		name     string
		input    athena.Athena
		expected bool
	}{
		{
			name: "AWS Athena workgroup doesn't enforce configuration",
			input: athena.Athena{
				Workgroups: []athena.Workgroup{
					{
						Metadata:             defsecTypes.NewTestMetadata(),
						EnforceConfiguration: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS Athena workgroup enforces configuration",
			input: athena.Athena{
				Workgroups: []athena.Workgroup{
					{
						Metadata:             defsecTypes.NewTestMetadata(),
						EnforceConfiguration: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.Athena = test.input
			results := CheckNoEncryptionOverride.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoEncryptionOverride.Rule().LongID() {
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
