package database

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/azure/database"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicFirewallAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    database.Database
		expected bool
	}{
		{
			name: "MySQL server firewall allows public internet access",
			input: database.Database{
				Metadata: types.NewTestMetadata(),
				MySQLServers: []database.MySQLServer{
					{
						Metadata: types.NewTestMetadata(),
						Server: database.Server{
							Metadata: types.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: types.NewTestMetadata(),
									StartIP:  types.String("0.0.0.0", types.NewTestMetadata()),
									EndIP:    types.String("255.255.255.255", types.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "MS SQL server firewall allows public internet access",
			input: database.Database{
				Metadata: types.NewTestMetadata(),
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: types.NewTestMetadata(),
						Server: database.Server{
							Metadata: types.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: types.NewTestMetadata(),
									StartIP:  types.String("0.0.0.0", types.NewTestMetadata()),
									EndIP:    types.String("255.255.255.255", types.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "PostgreSQL server firewall allows public internet access",
			input: database.Database{
				Metadata: types.NewTestMetadata(),
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: types.NewTestMetadata(),
						Server: database.Server{
							Metadata: types.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: types.NewTestMetadata(),
									StartIP:  types.String("0.0.0.0", types.NewTestMetadata()),
									EndIP:    types.String("255.255.255.255", types.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "MariaDB server firewall allows public internet access",
			input: database.Database{
				Metadata: types.NewTestMetadata(),
				MariaDBServers: []database.MariaDBServer{
					{
						Metadata: types.NewTestMetadata(),
						Server: database.Server{
							Metadata: types.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: types.NewTestMetadata(),
									StartIP:  types.String("0.0.0.0", types.NewTestMetadata()),
									EndIP:    types.String("255.255.255.255", types.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "MySQL server firewall allows access to Azure services",
			input: database.Database{
				Metadata: types.NewTestMetadata(),
				MySQLServers: []database.MySQLServer{
					{
						Metadata: types.NewTestMetadata(),
						Server: database.Server{
							Metadata: types.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: types.NewTestMetadata(),
									StartIP:  types.String("0.0.0.0", types.NewTestMetadata()),
									EndIP:    types.String("0.0.0.0", types.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "MS SQL server firewall allows access to Azure services",
			input: database.Database{
				Metadata: types.NewTestMetadata(),
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: types.NewTestMetadata(),
						Server: database.Server{
							Metadata: types.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: types.NewTestMetadata(),
									StartIP:  types.String("0.0.0.0", types.NewTestMetadata()),
									EndIP:    types.String("0.0.0.0", types.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "PostgreSQL server firewall allows access to Azure services",
			input: database.Database{
				Metadata: types.NewTestMetadata(),
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: types.NewTestMetadata(),
						Server: database.Server{
							Metadata: types.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: types.NewTestMetadata(),
									StartIP:  types.String("0.0.0.0", types.NewTestMetadata()),
									EndIP:    types.String("0.0.0.0", types.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "MariaDB server firewall allows access to Azure services",
			input: database.Database{
				Metadata: types.NewTestMetadata(),
				MariaDBServers: []database.MariaDBServer{
					{
						Metadata: types.NewTestMetadata(),
						Server: database.Server{
							Metadata: types.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: types.NewTestMetadata(),
									StartIP:  types.String("0.0.0.0", types.NewTestMetadata()),
									EndIP:    types.String("0.0.0.0", types.NewTestMetadata()),
								},
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
			testState.Azure.Database = test.input
			results := CheckNoPublicFirewallAccess.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckNoPublicFirewallAccess.Rule().LongID() {
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
