package datafactory

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/datafactory"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    datafactory.DataFactory
		expected bool
	}{
		{
			name: "Data Factory public access enabled",
			input: datafactory.DataFactory{
				Metadata: types.NewTestMetadata(),
				DataFactories: []datafactory.Factory{
					{
						Metadata:            types.NewTestMetadata(),
						EnablePublicNetwork: types.Bool(true, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Data Factory public access disabled",
			input: datafactory.DataFactory{
				Metadata: types.NewTestMetadata(),
				DataFactories: []datafactory.Factory{
					{
						Metadata:            types.NewTestMetadata(),
						EnablePublicNetwork: types.Bool(false, types.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Azure.DataFactory = test.input
			results := CheckNoPublicAccess.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicAccess.Rule().LongID() {
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
