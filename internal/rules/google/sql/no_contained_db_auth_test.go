package sql

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/sql"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoContainedDbAuth(t *testing.T) {
	tests := []struct {
		name     string
		input    sql.SQL
		expected bool
	}{
		{
			name: "Instance contained database authentication enabled",
			input: sql.SQL{
				Metadata: types.NewTestMetadata(),
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        types.NewTestMetadata(),
						DatabaseVersion: types.String("SQLSERVER_2017_STANDARD", types.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: types.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:                        types.NewTestMetadata(),
								ContainedDatabaseAuthentication: types.Bool(true, types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance contained database authentication disabled",
			input: sql.SQL{
				Metadata: types.NewTestMetadata(),
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        types.NewTestMetadata(),
						DatabaseVersion: types.String("SQLSERVER_2017_STANDARD", types.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: types.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:                        types.NewTestMetadata(),
								ContainedDatabaseAuthentication: types.Bool(false, types.NewTestMetadata()),
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
			results := CheckNoContainedDbAuth.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoContainedDbAuth.Rule().LongID() {
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
