package sql

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/sql"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckPgLogErrors(t *testing.T) {
	tests := []struct {
		name     string
		input    sql.SQL
		expected bool
	}{
		{
			name: "Instance minimum log severity set to PANIC",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        defsecTypes.NewTestMetadata(),
						DatabaseVersion: defsecTypes.String("POSTGRES_12", defsecTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: defsecTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:       defsecTypes.NewTestMetadata(),
								LogMinMessages: defsecTypes.String("PANIC", defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance minimum log severity set to ERROR",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        defsecTypes.NewTestMetadata(),
						DatabaseVersion: defsecTypes.String("POSTGRES_12", defsecTypes.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: defsecTypes.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:       defsecTypes.NewTestMetadata(),
								LogMinMessages: defsecTypes.String("ERROR", defsecTypes.NewTestMetadata()),
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
			results := CheckPgLogErrors.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckPgLogErrors.Rule().LongID() {
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
