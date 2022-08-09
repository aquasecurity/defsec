package sql

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/sql"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEncryptInTransitData(t *testing.T) {
	tests := []struct {
		name     string
		input    sql.SQL
		expected bool
	}{
		{
			name: "DB instance TLS not required",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Settings: sql.Settings{
							Metadata: defsecTypes.NewTestMetadata(),
							IPConfiguration: sql.IPConfiguration{
								Metadata:   defsecTypes.NewTestMetadata(),
								RequireTLS: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "DB instance TLS required",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Settings: sql.Settings{
							Metadata: defsecTypes.NewTestMetadata(),
							IPConfiguration: sql.IPConfiguration{
								Metadata:   defsecTypes.NewTestMetadata(),
								RequireTLS: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							},
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
			testState.Google.SQL = test.input
			results := CheckEncryptInTransitData.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEncryptInTransitData.Rule().LongID() {
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
