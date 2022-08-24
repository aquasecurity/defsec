package database

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

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
						Metadata: defsecTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: defsecTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: defsecTypes.NewTestMetadata(),
									StartIP:  defsecTypes.String("0.0.0.0", defsecTypes.NewTestMetadata()),
									EndIP:    defsecTypes.String("255.255.255.255", defsecTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "MySQL server firewall allows single public internet access",
			input: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: defsecTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: defsecTypes.NewTestMetadata(),
									StartIP:  defsecTypes.String("8.8.8.8", defsecTypes.NewTestMetadata()),
									EndIP:    defsecTypes.String("8.8.8.8", defsecTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "MS SQL server firewall allows public internet access",
			input: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: defsecTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: defsecTypes.NewTestMetadata(),
									StartIP:  defsecTypes.String("0.0.0.0", defsecTypes.NewTestMetadata()),
									EndIP:    defsecTypes.String("255.255.255.255", defsecTypes.NewTestMetadata()),
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
						Metadata: defsecTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: defsecTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: defsecTypes.NewTestMetadata(),
									StartIP:  defsecTypes.String("0.0.0.0", defsecTypes.NewTestMetadata()),
									EndIP:    defsecTypes.String("255.255.255.255", defsecTypes.NewTestMetadata()),
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
						Metadata: defsecTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: defsecTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: defsecTypes.NewTestMetadata(),
									StartIP:  defsecTypes.String("0.0.0.0", defsecTypes.NewTestMetadata()),
									EndIP:    defsecTypes.String("255.255.255.255", defsecTypes.NewTestMetadata()),
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
						Metadata: defsecTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: defsecTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: defsecTypes.NewTestMetadata(),
									StartIP:  defsecTypes.String("0.0.0.0", defsecTypes.NewTestMetadata()),
									EndIP:    defsecTypes.String("0.0.0.0", defsecTypes.NewTestMetadata()),
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
						Metadata: defsecTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: defsecTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: defsecTypes.NewTestMetadata(),
									StartIP:  defsecTypes.String("0.0.0.0", defsecTypes.NewTestMetadata()),
									EndIP:    defsecTypes.String("0.0.0.0", defsecTypes.NewTestMetadata()),
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
						Metadata: defsecTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: defsecTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: defsecTypes.NewTestMetadata(),
									StartIP:  defsecTypes.String("0.0.0.0", defsecTypes.NewTestMetadata()),
									EndIP:    defsecTypes.String("0.0.0.0", defsecTypes.NewTestMetadata()),
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
						Metadata: defsecTypes.NewTestMetadata(),
						Server: database.Server{
							Metadata: defsecTypes.NewTestMetadata(),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: defsecTypes.NewTestMetadata(),
									StartIP:  defsecTypes.String("0.0.0.0", defsecTypes.NewTestMetadata()),
									EndIP:    defsecTypes.String("0.0.0.0", defsecTypes.NewTestMetadata()),
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
