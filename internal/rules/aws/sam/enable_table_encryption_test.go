package sam

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/sam"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableTableEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    sam.SAM
		expected bool
	}{
		{
			name: "SAM simple table SSE disabled",
			input: sam.SAM{
				Metadata: types.NewTestMetadata(),
				SimpleTables: []sam.SimpleTable{
					{
						Metadata: types.NewTestMetadata(),
						SSESpecification: sam.SSESpecification{
							Metadata: types.NewTestMetadata(),
							Enabled:  types.Bool(false, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "SAM simple table SSE enabled",
			input: sam.SAM{
				Metadata: types.NewTestMetadata(),
				SimpleTables: []sam.SimpleTable{
					{
						Metadata: types.NewTestMetadata(),
						SSESpecification: sam.SSESpecification{
							Metadata: types.NewTestMetadata(),
							Enabled:  types.Bool(true, types.NewTestMetadata()),
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
			testState.AWS.SAM = test.input
			results := CheckEnableTableEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableTableEncryption.Rule().LongID() {
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
