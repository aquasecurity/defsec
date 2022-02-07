package database

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/azure/database"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/defsec/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckPostgresConfigurationLogConnectionThrottling(t *testing.T) {
	tests := []struct {
		name     string
		input    database.Database
		expected bool
	}{
		{
			name: "PostgreSQL server connection throttling disabled",
			input: database.Database{
				Metadata: types.NewTestMetadata(),
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: types.NewTestMetadata(),
						Config: database.PostgresSQLConfig{
							Metadata:             types.NewTestMetadata(),
							ConnectionThrottling: types.Bool(false, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "PostgreSQL server connection throttling enabled",
			input: database.Database{
				Metadata: types.NewTestMetadata(),
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: types.NewTestMetadata(),
						Config: database.PostgresSQLConfig{
							Metadata:             types.NewTestMetadata(),
							ConnectionThrottling: types.Bool(true, types.NewTestMetadata()),
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
			results := CheckPostgresConfigurationLogConnectionThrottling.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckPostgresConfigurationLogConnectionThrottling.Rule().LongID() {
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
