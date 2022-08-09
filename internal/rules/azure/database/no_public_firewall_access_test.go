package database

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/database"
	"github.com/aquasecurity/defsec/pkg/scan"

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
				MySQLServers: []database.MySQLServer{
					{
						Metadata: types2.NewTestMetadata(),
						Server: database.Server{
							Metadata: types2.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: types2.NewTestMetadata(),
									StartIP:  types2.String("0.0.0.0", types2.NewTestMetadata()),
									EndIP:    types2.String("255.255.255.255", types2.NewTestMetadata()),
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
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: types2.NewTestMetadata(),
						Server: database.Server{
							Metadata: types2.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: types2.NewTestMetadata(),
									StartIP:  types2.String("0.0.0.0", types2.NewTestMetadata()),
									EndIP:    types2.String("255.255.255.255", types2.NewTestMetadata()),
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
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: types2.NewTestMetadata(),
						Server: database.Server{
							Metadata: types2.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: types2.NewTestMetadata(),
									StartIP:  types2.String("0.0.0.0", types2.NewTestMetadata()),
									EndIP:    types2.String("255.255.255.255", types2.NewTestMetadata()),
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
				MariaDBServers: []database.MariaDBServer{
					{
						Metadata: types2.NewTestMetadata(),
						Server: database.Server{
							Metadata: types2.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: types2.NewTestMetadata(),
									StartIP:  types2.String("0.0.0.0", types2.NewTestMetadata()),
									EndIP:    types2.String("255.255.255.255", types2.NewTestMetadata()),
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
				MySQLServers: []database.MySQLServer{
					{
						Metadata: types2.NewTestMetadata(),
						Server: database.Server{
							Metadata: types2.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: types2.NewTestMetadata(),
									StartIP:  types2.String("0.0.0.0", types2.NewTestMetadata()),
									EndIP:    types2.String("0.0.0.0", types2.NewTestMetadata()),
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
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: types2.NewTestMetadata(),
						Server: database.Server{
							Metadata: types2.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: types2.NewTestMetadata(),
									StartIP:  types2.String("0.0.0.0", types2.NewTestMetadata()),
									EndIP:    types2.String("0.0.0.0", types2.NewTestMetadata()),
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
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: types2.NewTestMetadata(),
						Server: database.Server{
							Metadata: types2.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: types2.NewTestMetadata(),
									StartIP:  types2.String("0.0.0.0", types2.NewTestMetadata()),
									EndIP:    types2.String("0.0.0.0", types2.NewTestMetadata()),
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
				MariaDBServers: []database.MariaDBServer{
					{
						Metadata: types2.NewTestMetadata(),
						Server: database.Server{
							Metadata: types2.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: types2.NewTestMetadata(),
									StartIP:  types2.String("0.0.0.0", types2.NewTestMetadata()),
									EndIP:    types2.String("0.0.0.0", types2.NewTestMetadata()),
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
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicFirewallAccess.Rule().LongID() {
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
