package neptune

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/provider/aws/neptune"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckEnableLogExport(t *testing.T) {
	tests := []struct {
		name     string
		input    neptune.Neptune
		expected bool
	}{
		{
			name: "Neptune Cluster with audit logging disabled",
			input: neptune.Neptune{
				Metadata: types.NewTestMetadata(),
				Clusters: []neptune.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						Logging: neptune.Logging{
							Metadata: types.NewTestMetadata(),
							Audit:    types.Bool(false, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Neptune Cluster with audit logging enabled",
			input: neptune.Neptune{
				Metadata: types.NewTestMetadata(),
				Clusters: []neptune.Cluster{
					{
						Metadata: types.NewTestMetadata(),
						Logging: neptune.Logging{
							Metadata: types.NewTestMetadata(),
							Audit:    types.Bool(true, types.NewTestMetadata()),
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
			testState.AWS.Neptune = test.input
			results := CheckEnableLogExport.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckEnableLogExport.Rule().LongID() {
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
