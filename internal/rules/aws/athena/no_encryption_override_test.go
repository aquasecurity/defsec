package athena

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

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
				Metadata: types.NewTestMetadata(),
				Workgroups: []athena.Workgroup{
					{
						Metadata:             types.NewTestMetadata(),
						EnforceConfiguration: types.Bool(false, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS Athena workgroup enforces configuration",
			input: athena.Athena{
				Metadata: types.NewTestMetadata(),
				Workgroups: []athena.Workgroup{
					{
						Metadata:             types.NewTestMetadata(),
						EnforceConfiguration: types.Bool(true, types.NewTestMetadata()),
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
