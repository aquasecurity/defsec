package database

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/database"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckPostgresConfigurationLogCheckpoints(t *testing.T) {
	tests := []struct {
		name     string
		input    database.Database
		expected bool
	}{
		{
			name: "PostgreSQL server checkpoint logging disabled",
			input: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Config: database.PostgresSQLConfig{
							Metadata:       defsecTypes.NewTestMetadata(),
							LogCheckpoints: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "PostgreSQL server checkpoint logging enabled",
			input: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Config: database.PostgresSQLConfig{
							Metadata:       defsecTypes.NewTestMetadata(),
							LogCheckpoints: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
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
			testState.Azure.Database = test.input
			results := CheckPostgresConfigurationLogCheckpoints.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckPostgresConfigurationLogCheckpoints.Rule().LongID() {
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
