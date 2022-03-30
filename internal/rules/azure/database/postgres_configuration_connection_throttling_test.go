package database

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/database"
	"github.com/aquasecurity/defsec/pkg/scan"

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
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckPostgresConfigurationLogConnectionThrottling.Rule().LongID() {
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
