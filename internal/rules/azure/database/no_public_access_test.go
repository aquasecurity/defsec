package database

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/database"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    database.Database
		expected bool
	}{
		{
			name: "MySQL server public access enabled",
			input: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  defsecTypes.NewTestMetadata(),
							EnablePublicNetworkAccess: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "MariaDB server public access enabled",
			input: database.Database{
				MariaDBServers: []database.MariaDBServer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  defsecTypes.NewTestMetadata(),
							EnablePublicNetworkAccess: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "MS SQL server public access enabled",
			input: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  defsecTypes.NewTestMetadata(),
							EnablePublicNetworkAccess: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "PostgreSQL server public access enabled",
			input: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  defsecTypes.NewTestMetadata(),
							EnablePublicNetworkAccess: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "MySQL server public access disabled",
			input: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  defsecTypes.NewTestMetadata(),
							EnablePublicNetworkAccess: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "MariaDB server public access disabled",
			input: database.Database{
				MariaDBServers: []database.MariaDBServer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  defsecTypes.NewTestMetadata(),
							EnablePublicNetworkAccess: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "MS SQL server public access disabled",
			input: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  defsecTypes.NewTestMetadata(),
							EnablePublicNetworkAccess: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "PostgreSQL server public access disabled",
			input: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  defsecTypes.NewTestMetadata(),
							EnablePublicNetworkAccess: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
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
