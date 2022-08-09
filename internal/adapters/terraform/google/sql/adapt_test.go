package sql

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/google/sql"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  sql.SQL
	}{
		{
			name: "default flags",
			terraform: `
			resource "google_sql_database_instance" "db" {
				database_version = "POSTGRES_12"
				settings {
					backup_configuration {
						enabled = true
					}
					ip_configuration {
						ipv4_enabled = false
						authorized_networks {
							value           = "108.12.12.0/24"
							name            = "internal"
						}
						require_ssl = true
					}
				}
			}
`,
			expected: sql.SQL{
				Instances: []sql.DatabaseInstance{
					{
						Metadata:        types2.NewTestMetadata(),
						IsReplica:       types2.Bool(false, types2.NewTestMetadata()),
						DatabaseVersion: types2.String("POSTGRES_12", types2.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: types2.NewTestMetadata(),
							Backups: sql.Backups{
								Metadata: types2.NewTestMetadata(),
								Enabled:  types2.Bool(true, types2.NewTestMetadata()),
							},
							Flags: sql.Flags{
								Metadata:                        types2.NewTestMetadata(),
								LogMinDurationStatement:         types2.Int(-1, types2.NewTestMetadata()),
								ContainedDatabaseAuthentication: types2.Bool(true, types2.NewTestMetadata()),
								CrossDBOwnershipChaining:        types2.Bool(true, types2.NewTestMetadata()),
								LocalInFile:                     types2.Bool(false, types2.NewTestMetadata()),
								LogCheckpoints:                  types2.Bool(false, types2.NewTestMetadata()),
								LogConnections:                  types2.Bool(false, types2.NewTestMetadata()),
								LogDisconnections:               types2.Bool(false, types2.NewTestMetadata()),
								LogLockWaits:                    types2.Bool(false, types2.NewTestMetadata()),
								LogMinMessages:                  types2.String("", types2.NewTestMetadata()),
								LogTempFileSize:                 types2.Int(-1, types2.NewTestMetadata()),
							},
							IPConfiguration: sql.IPConfiguration{
								Metadata:   types2.NewTestMetadata(),
								RequireTLS: types2.Bool(true, types2.NewTestMetadata()),
								EnableIPv4: types2.Bool(false, types2.NewTestMetadata()),
								AuthorizedNetworks: []struct {
									Name types2.StringValue
									CIDR types2.StringValue
								}{
									{
										Name: types2.String("internal", types2.NewTestMetadata()),
										CIDR: types2.String("108.12.12.0/24", types2.NewTestMetadata()),
									},
								},
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

func Test_adaptInstances(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  []sql.DatabaseInstance
	}{
		{
			name: "all flags",
			terraform: `
resource "google_sql_database_instance" "backup_source_instance" {
  name             = "test-instance"
  database_version = "POSTGRES_11"

  project             = "test-project"
  region              = "europe-west6"
  deletion_protection = false
  settings {
    tier = "db-f1-micro"
    backup_configuration {
      enabled = true
    }
    ip_configuration {
      ipv4_enabled    = false
      private_network = "test-network"
      require_ssl     = true
    }
    database_flags {
      name  = "log_connections"
      value = "on"
    }
    database_flags {
      name  = "log_temp_files"
      value = "0"
    }
    database_flags {
      name  = "log_checkpoints"
      value = "on"
    }
    database_flags {
      name  = "log_disconnections"
      value = "on"
    }
    database_flags {
      name  = "log_lock_waits"
      value = "on"
    }
  }
}
                `,
			expected: []sql.DatabaseInstance{
				{
					Metadata:        types2.NewTestMetadata(),
					DatabaseVersion: types2.String("POSTGRES_11", types2.NewTestMetadata()),
					IsReplica:       types2.Bool(false, types2.NewTestMetadata()),
					Settings: sql.Settings{
						Backups: sql.Backups{
							Enabled: types2.Bool(true, types2.NewTestMetadata()),
						},
						Flags: sql.Flags{
							LogConnections:                  types2.Bool(true, types2.NewTestMetadata()),
							LogTempFileSize:                 types2.Int(0, types2.NewTestMetadata()),
							LogCheckpoints:                  types2.Bool(true, types2.NewTestMetadata()),
							LogDisconnections:               types2.Bool(true, types2.NewTestMetadata()),
							LogLockWaits:                    types2.Bool(true, types2.NewTestMetadata()),
							ContainedDatabaseAuthentication: types2.Bool(true, types2.NewTestMetadata()),
							CrossDBOwnershipChaining:        types2.Bool(true, types2.NewTestMetadata()),
							LocalInFile:                     types2.Bool(false, types2.NewTestMetadata()),
							LogMinDurationStatement:         types2.Int(-1, types2.NewTestMetadata()),
							LogMinMessages:                  types2.String("", types2.NewTestMetadata()),
						},
						IPConfiguration: sql.IPConfiguration{
							EnableIPv4: types2.Bool(false, types2.NewTestMetadata()),
							RequireTLS: types2.Bool(true, types2.NewTestMetadata()),
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptInstances(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "google_sql_database_instance" "backup_source_instance" {
		name             = "test-instance"
		database_version = "POSTGRES_11"
	  
		settings {
		  backup_configuration {
			enabled = true
		  }

		  ip_configuration {
			ipv4_enabled    = false
			require_ssl     = true
			authorized_networks {
				name            = "internal"
				value           = "108.12.12.0/24"
			}
		  }

		  database_flags {
			name  = "log_connections"
			value = "on"
		  }
		  database_flags {
			name  = "log_temp_files"
			value = "0"
		  }
		  database_flags {
			name  = "log_checkpoints"
			value = "on"
		  }
		  database_flags {
			name  = "log_disconnections"
			value = "on"
		  }
		  database_flags {
			name  = "log_lock_waits"
			value = "on"
		  }
		}
	  }`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Instances, 1)
	instance := adapted.Instances[0]

	assert.Equal(t, 2, instance.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 41, instance.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, instance.DatabaseVersion.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, instance.DatabaseVersion.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 6, instance.Settings.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 40, instance.Settings.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 7, instance.Settings.Backups.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 9, instance.Settings.Backups.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 8, instance.Settings.Backups.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 8, instance.Settings.Backups.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, instance.Settings.IPConfiguration.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 18, instance.Settings.IPConfiguration.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 12, instance.Settings.IPConfiguration.EnableIPv4.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 12, instance.Settings.IPConfiguration.EnableIPv4.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 13, instance.Settings.IPConfiguration.RequireTLS.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 13, instance.Settings.IPConfiguration.RequireTLS.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 15, instance.Settings.IPConfiguration.AuthorizedNetworks[0].Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 15, instance.Settings.IPConfiguration.AuthorizedNetworks[0].Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 16, instance.Settings.IPConfiguration.AuthorizedNetworks[0].CIDR.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 16, instance.Settings.IPConfiguration.AuthorizedNetworks[0].CIDR.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 22, instance.Settings.Flags.LogConnections.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 22, instance.Settings.Flags.LogConnections.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 25, instance.Settings.Flags.LogTempFileSize.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 25, instance.Settings.Flags.LogTempFileSize.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 34, instance.Settings.Flags.LogDisconnections.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 34, instance.Settings.Flags.LogDisconnections.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 38, instance.Settings.Flags.LogLockWaits.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 38, instance.Settings.Flags.LogLockWaits.GetMetadata().Range().GetEndLine())

}
