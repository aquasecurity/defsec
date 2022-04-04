package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/cloudstack/compute"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoSensitiveInfo(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Compute instance with sensitive information in user data",
			input: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: types.NewTestMetadata(),
						UserData: types.String(` export DATABASE_PASSWORD=\"SomeSortOfPassword\"`, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Compute instance with no sensitive information in user data",
			input: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: types.NewTestMetadata(),
						UserData: types.String(` export GREETING="Hello there"`, types.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.CloudStack.Compute = test.input
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
