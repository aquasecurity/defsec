package database

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/database"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckSecureTlsPolicy(t *testing.T) {
	tests := []struct {
		name     string
		input    database.Database
		expected bool
	}{
		{
			name: "MS SQL server minimum TLS version 1.0",
			input: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: types2.NewTestMetadata(),
						Server: database.Server{
							Metadata:          types2.NewTestMetadata(),
							MinimumTLSVersion: types2.String("1.0", types2.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "MySQL server minimum TLS version 1.0",
			input: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: types2.NewTestMetadata(),
						Server: database.Server{
							Metadata:          types2.NewTestMetadata(),
							MinimumTLSVersion: types2.String("TLS1_0", types2.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "PostgreSQL server minimum TLS version 1.0",
			input: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: types2.NewTestMetadata(),
						Server: database.Server{
							Metadata:          types2.NewTestMetadata(),
							MinimumTLSVersion: types2.String("TLS1_0", types2.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "MS SQL server minimum TLS version 1.2",
			input: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: types2.NewTestMetadata(),
						Server: database.Server{
							Metadata:          types2.NewTestMetadata(),
							MinimumTLSVersion: types2.String("1.2", types2.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "MySQL server minimum TLS version 1.2",
			input: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: types2.NewTestMetadata(),
						Server: database.Server{
							Metadata:          types2.NewTestMetadata(),
							MinimumTLSVersion: types2.String("TLS1_2", types2.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "PostgreSQL server minimum TLS version 1.2",
			input: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: types2.NewTestMetadata(),
						Server: database.Server{
							Metadata:          types2.NewTestMetadata(),
							MinimumTLSVersion: types2.String("TLS1_2", types2.NewTestMetadata()),
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
			results := CheckSecureTlsPolicy.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckSecureTlsPolicy.Rule().LongID() {
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
