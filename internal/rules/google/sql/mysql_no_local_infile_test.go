package sql

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/sql"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckMysqlNoLocalInfile(t *testing.T) {
	tests := []struct {
		name     string
		input    sql.SQL
		expected bool
	}{
		{
			name: "DB instance local file read access enabled",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        types2.NewTestMetadata(),
						DatabaseVersion: types2.String("MYSQL_5_6", types2.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: types2.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:    types2.NewTestMetadata(),
								LocalInFile: types2.Bool(true, types2.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "DB instance local file read access disabled",
			input: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        types2.NewTestMetadata(),
						DatabaseVersion: types2.String("MYSQL_5_6", types2.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: types2.NewTestMetadata(),
							Flags: sql.Flags{
								Metadata:    types2.NewTestMetadata(),
								LocalInFile: types2.Bool(false, types2.NewTestMetadata()),
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
			results := CheckMysqlNoLocalInfile.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckMysqlNoLocalInfile.Rule().LongID() {
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
