package database

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/database"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableSslEnforcement(t *testing.T) {
	tests := []struct {
		name     string
		input    database.Database
		expected bool
	}{
		{
			name: "MariaDB server SSL not enforced",
			input: database.Database{
				MariaDBServers: []database.MariaDBServer{
					{
						Metadata: types.NewTestMetadata(),
						Server: database.Server{
							Metadata:             types.NewTestMetadata(),
							EnableSSLEnforcement: types.Bool(false, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "MySQL server SSL not enforced",
			input: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: types.NewTestMetadata(),
						Server: database.Server{
							Metadata:             types.NewTestMetadata(),
							EnableSSLEnforcement: types.Bool(false, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "PostgreSQL server SSL not enforced",
			input: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: types.NewTestMetadata(),
						Server: database.Server{
							Metadata:             types.NewTestMetadata(),
							EnableSSLEnforcement: types.Bool(false, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "MariaDB server SSL enforced",
			input: database.Database{
				MariaDBServers: []database.MariaDBServer{
					{
						Metadata: types.NewTestMetadata(),
						Server: database.Server{
							Metadata:             types.NewTestMetadata(),
							EnableSSLEnforcement: types.Bool(true, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "MySQL server SSL enforced",
			input: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: types.NewTestMetadata(),
						Server: database.Server{
							Metadata:             types.NewTestMetadata(),
							EnableSSLEnforcement: types.Bool(true, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "PostgreSQL server SSL enforced",
			input: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: types.NewTestMetadata(),
						Server: database.Server{
							Metadata:             types.NewTestMetadata(),
							EnableSSLEnforcement: types.Bool(true, types.NewTestMetadata()),
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
			results := CheckEnableSslEnforcement.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableSslEnforcement.Rule().LongID() {
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
