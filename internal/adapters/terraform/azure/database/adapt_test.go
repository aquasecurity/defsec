package database

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/azure/database"
	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  database.Database
	}{
		{
			name: "postgresql",
			terraform: `
			resource "azurerm_postgresql_server" "example" {
				name                = "example"
			  
				public_network_access_enabled    = true
				ssl_enforcement_enabled          = true
				ssl_minimal_tls_version_enforced = "TLS1_2"
			  }

			  resource "azurerm_postgresql_configuration" "example" {
				name                = "log_connections"
				resource_group_name = azurerm_resource_group.example.name
				server_name         = azurerm_postgresql_server.example.name
				value               = "on"
			  }

			  resource "azurerm_postgresql_configuration" "example" {
				name                = "log_checkpoints"
				resource_group_name = azurerm_resource_group.example.name
				server_name         = azurerm_postgresql_server.example.name
				value               = "on"
			  }

			  resource "azurerm_postgresql_configuration" "example" {
				name                = "connection_throttling"
				resource_group_name = azurerm_resource_group.example.name
				server_name         = azurerm_postgresql_server.example.name
				value               = "on"
			  }

			  resource "azurerm_postgresql_firewall_rule" "example" {
				name                = "office"
				resource_group_name = azurerm_resource_group.example.name
				server_name         = azurerm_postgresql_server.example.name
				start_ip_address    = "40.112.8.12"
				end_ip_address      = "40.112.8.12"
			  }
`,
			expected: database.Database{
				PostgreSQLServers: []database.PostgreSQLServer{
					{
						Metadata: types.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  types.NewTestMetadata(),
							EnableSSLEnforcement:      types.Bool(true, types.NewTestMetadata()),
							MinimumTLSVersion:         types.String("TLS1_2", types.NewTestMetadata()),
							EnablePublicNetworkAccess: types.Bool(true, types.NewTestMetadata()),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: types.NewTestMetadata(),
									StartIP:  types.String("40.112.8.12", types.NewTestMetadata()),
									EndIP:    types.String("40.112.8.12", types.NewTestMetadata()),
								},
							},
						},
						Config: database.PostgresSQLConfig{
							Metadata:             types.NewTestMetadata(),
							LogConnections:       types.Bool(true, types.NewTestMetadata()),
							LogCheckpoints:       types.Bool(true, types.NewTestMetadata()),
							ConnectionThrottling: types.Bool(true, types.NewTestMetadata()),
						},
					},
				},
			},
		},
		{
			name: "mariadb",
			terraform: `
			resource "azurerm_mariadb_server" "example" {
				name                = "example-mariadb-server"
				location            = azurerm_resource_group.example.location
				resource_group_name = azurerm_resource_group.example.name
			  
				public_network_access_enabled = false
				ssl_enforcement_enabled       = true
			  }

			  resource "azurerm_mariadb_firewall_rule" "example" {
				name                = "test-rule"
				server_name         = azurerm_mariadb_server.example.name
				start_ip_address    = "40.112.0.0"
				end_ip_address      = "40.112.255.255"
			  }
`,
			expected: database.Database{
				MariaDBServers: []database.MariaDBServer{
					{
						Metadata: types.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  types.NewTestMetadata(),
							EnableSSLEnforcement:      types.Bool(true, types.NewTestMetadata()),
							EnablePublicNetworkAccess: types.Bool(false, types.NewTestMetadata()),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: types.NewTestMetadata(),
									StartIP:  types.String("40.112.0.0", types.NewTestMetadata()),
									EndIP:    types.String("40.112.255.255", types.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "mysql",
			terraform: `
			resource "azurerm_mysql_server" "example" {
				public_network_access_enabled     = true
				ssl_enforcement_enabled           = true
				ssl_minimal_tls_version_enforced  = "TLS1_2"
			  }

			  resource "azurerm_mysql_firewall_rule" "example" {
				server_name         = azurerm_mysql_server.example.name
				start_ip_address    = "40.112.8.12"
				end_ip_address      = "40.112.8.12"
			  }
			`,
			expected: database.Database{
				MySQLServers: []database.MySQLServer{
					{
						Metadata: types.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  types.NewTestMetadata(),
							EnableSSLEnforcement:      types.Bool(true, types.NewTestMetadata()),
							MinimumTLSVersion:         types.String("TLS1_2", types.NewTestMetadata()),
							EnablePublicNetworkAccess: types.Bool(true, types.NewTestMetadata()),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: types.NewTestMetadata(),
									StartIP:  types.String("40.112.8.12", types.NewTestMetadata()),
									EndIP:    types.String("40.112.8.12", types.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
		},
		{
			name: "ms sql",
			terraform: `
			resource "azurerm_mssql_server" "example" {
				name                          = "mssqlserver"
				minimum_tls_version           = "1.2"
				public_network_access_enabled = false
			  }

			  resource "azurerm_mssql_firewall_rule" "example" {
				name             = "FirewallRule1"
				server_id        = azurerm_mssql_server.example.id
				start_ip_address = "10.0.17.62"
				end_ip_address   = "10.0.17.62"
			  }

			  resource "azurerm_mssql_server_security_alert_policy" "example" {
				resource_group_name        = azurerm_resource_group.example.name
				server_name                = azurerm_mssql_server.example.name
				disabled_alerts = [
				  "Sql_Injection",
				  "Data_Exfiltration"
				]
				email_account_admins = true
				email_addresses = [
					"example@example.com"
				]
			  }

			  resource "azurerm_mssql_server_extended_auditing_policy" "example" {
				server_id                               = azurerm_mssql_server.example.id
				retention_in_days                       = 6
			  }
			`,
			expected: database.Database{
				MSSQLServers: []database.MSSQLServer{
					{
						Metadata: types.NewTestMetadata(),
						Server: database.Server{
							Metadata:                  types.NewTestMetadata(),
							MinimumTLSVersion:         types.String("1.2", types.NewTestMetadata()),
							EnablePublicNetworkAccess: types.Bool(false, types.NewTestMetadata()),
							EnableSSLEnforcement:      types.Bool(false, types.NewTestMetadata()),
							FirewallRules: []database.FirewallRule{
								{
									Metadata: types.NewTestMetadata(),
									StartIP:  types.String("10.0.17.62", types.NewTestMetadata()),
									EndIP:    types.String("10.0.17.62", types.NewTestMetadata()),
								},
							},
						},
						ExtendedAuditingPolicies: []database.ExtendedAuditingPolicy{
							{
								Metadata:        types.NewTestMetadata(),
								RetentionInDays: types.Int(6, types.NewTestMetadata()),
							},
						},
						SecurityAlertPolicies: []database.SecurityAlertPolicy{
							{
								Metadata: types.NewTestMetadata(),
								EmailAddresses: []types.StringValue{
									types.String("example@example.com", types.NewTestMetadata()),
								},
								DisabledAlerts: []types.StringValue{
									types.String("Sql_Injection", types.NewTestMetadata()),
									types.String("Data_Exfiltration", types.NewTestMetadata()),
								},
								EmailAccountAdmins: types.Bool(true, types.NewTestMetadata()),
							},
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "azurerm_postgresql_server" "example" {
		public_network_access_enabled    = true
		ssl_enforcement_enabled          = true
		ssl_minimal_tls_version_enforced = "TLS1_2"
	  }

	  resource "azurerm_postgresql_configuration" "example" {
		name                = "log_connections"
		server_name         = azurerm_postgresql_server.example.name
		value               = "on"
	  }

	  resource "azurerm_postgresql_configuration" "example" {
		name                = "log_checkpoints"
		server_name         = azurerm_postgresql_server.example.name
		value               = "on"
	  }

	  resource "azurerm_postgresql_configuration" "example" {
		name                = "connection_throttling"
		server_name         = azurerm_postgresql_server.example.name
		value               = "on"
	  }

	  resource "azurerm_postgresql_firewall_rule" "example" {
		name                = "office"
		server_name         = azurerm_postgresql_server.example.name
		start_ip_address    = "40.112.8.12"
		end_ip_address      = "40.112.8.12"
	  }

	  resource "azurerm_mariadb_server" "example" {	  
		public_network_access_enabled = false
		ssl_enforcement_enabled       = true
	  }

	  resource "azurerm_mariadb_firewall_rule" "example" {
		name                = "test-rule"
		server_name         = azurerm_mariadb_server.example.name
		start_ip_address    = "40.112.0.0"
		end_ip_address      = "40.112.255.255"
	  }

	  resource "azurerm_mysql_server" "example" {
		public_network_access_enabled     = true
		ssl_enforcement_enabled           = true
		ssl_minimal_tls_version_enforced  = "TLS1_2"
	  }

	  resource "azurerm_mysql_firewall_rule" "example" {
		server_name         = azurerm_mysql_server.example.name
		start_ip_address    = "40.112.8.12"
		end_ip_address      = "40.112.8.12"
	  }

	  resource "azurerm_mssql_server" "example" {
		name                          = "mssqlserver"
		public_network_access_enabled = false
		minimum_tls_version           = "1.2"
	  }

	  resource "azurerm_mssql_firewall_rule" "example" {
		name             = "FirewallRule1"
		server_id        = azurerm_mssql_server.example.id
		start_ip_address = "10.0.17.62"
		end_ip_address   = "10.0.17.62"
	  }

	  resource "azurerm_mssql_server_security_alert_policy" "example" {
		server_name                = azurerm_mssql_server.example.name
		disabled_alerts = [
		  "Sql_Injection",
		  "Data_Exfiltration"
		]
		email_account_admins = true
		email_addresses = [
			"example@example.com"
		]
	  }

	  resource "azurerm_mssql_server_extended_auditing_policy" "example" {
		server_id                               = azurerm_mssql_server.example.id
		retention_in_days                       = 6
	  }
	`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.PostgreSQLServers, 1)
	require.Len(t, adapted.MariaDBServers, 1)
	require.Len(t, adapted.MySQLServers, 1)
	require.Len(t, adapted.MSSQLServers, 1)

	postgres := adapted.PostgreSQLServers[0]
	mariadb := adapted.MariaDBServers[0]
	mysql := adapted.MySQLServers[0]
	mssql := adapted.MSSQLServers[0]

	assert.Equal(t, 2, postgres.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, postgres.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 3, postgres.EnablePublicNetworkAccess.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, postgres.EnablePublicNetworkAccess.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, postgres.EnableSSLEnforcement.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, postgres.EnableSSLEnforcement.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, postgres.MinimumTLSVersion.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, postgres.MinimumTLSVersion.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, postgres.Config.LogConnections.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, postgres.Config.LogConnections.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 17, postgres.Config.LogCheckpoints.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 17, postgres.Config.LogCheckpoints.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 23, postgres.Config.ConnectionThrottling.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 23, postgres.Config.ConnectionThrottling.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 26, postgres.FirewallRules[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 31, postgres.FirewallRules[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 29, postgres.FirewallRules[0].StartIP.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 29, postgres.FirewallRules[0].StartIP.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 30, postgres.FirewallRules[0].EndIP.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 30, postgres.FirewallRules[0].EndIP.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 33, mariadb.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 36, mariadb.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 34, mariadb.EnablePublicNetworkAccess.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 34, mariadb.EnablePublicNetworkAccess.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 35, mariadb.EnableSSLEnforcement.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 35, mariadb.EnableSSLEnforcement.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 38, mariadb.FirewallRules[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 43, mariadb.FirewallRules[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 41, mariadb.FirewallRules[0].StartIP.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 41, mariadb.FirewallRules[0].StartIP.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 42, mariadb.FirewallRules[0].EndIP.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 42, mariadb.FirewallRules[0].EndIP.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 45, mysql.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 49, mysql.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 46, mysql.EnablePublicNetworkAccess.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 46, mysql.EnablePublicNetworkAccess.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 47, mysql.EnableSSLEnforcement.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 47, mysql.EnableSSLEnforcement.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 48, mysql.MinimumTLSVersion.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 48, mysql.MinimumTLSVersion.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 51, mysql.FirewallRules[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 55, mysql.FirewallRules[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 53, mysql.FirewallRules[0].StartIP.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 53, mysql.FirewallRules[0].StartIP.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 54, mysql.FirewallRules[0].EndIP.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 54, mysql.FirewallRules[0].EndIP.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 57, mssql.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 61, mssql.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 59, mssql.EnablePublicNetworkAccess.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 59, mssql.EnablePublicNetworkAccess.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 60, mssql.MinimumTLSVersion.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 60, mssql.MinimumTLSVersion.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 63, mssql.FirewallRules[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 68, mssql.FirewallRules[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 66, mssql.FirewallRules[0].StartIP.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 66, mssql.FirewallRules[0].StartIP.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 67, mssql.FirewallRules[0].EndIP.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 67, mssql.FirewallRules[0].EndIP.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 70, mssql.SecurityAlertPolicies[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 80, mssql.SecurityAlertPolicies[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 72, mssql.SecurityAlertPolicies[0].DisabledAlerts[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 75, mssql.SecurityAlertPolicies[0].DisabledAlerts[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 76, mssql.SecurityAlertPolicies[0].EmailAccountAdmins.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 76, mssql.SecurityAlertPolicies[0].EmailAccountAdmins.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 77, mssql.SecurityAlertPolicies[0].EmailAddresses[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 79, mssql.SecurityAlertPolicies[0].EmailAddresses[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 82, mssql.ExtendedAuditingPolicies[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 85, mssql.ExtendedAuditingPolicies[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 84, mssql.ExtendedAuditingPolicies[0].RetentionInDays.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 84, mssql.ExtendedAuditingPolicies[0].RetentionInDays.GetMetadata().Range().GetEndLine())
}
