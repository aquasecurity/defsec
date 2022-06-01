package sql

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"
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
						Metadata:        types.NewTestMetadata(),
						IsReplica:       types.Bool(false, types.NewTestMetadata()),
						DatabaseVersion: types.String("POSTGRES_12", types.NewTestMetadata()),
						Settings: sql.Settings{
							Metadata: types.NewTestMetadata(),
							Backups: sql.Backups{
								Metadata: types.NewTestMetadata(),
								Enabled:  types.Bool(true, types.NewTestMetadata()),
							},
							Flags: sql.Flags{
								Metadata:                        types.NewTestMetadata(),
								LogMinDurationStatement:         types.Int(-1, types.NewTestMetadata()),
								ContainedDatabaseAuthentication: types.Bool(true, types.NewTestMetadata()),
								CrossDBOwnershipChaining:        types.Bool(true, types.NewTestMetadata()),
								LocalInFile:                     types.Bool(false, types.NewTestMetadata()),
								LogCheckpoints:                  types.Bool(false, types.NewTestMetadata()),
								LogConnections:                  types.Bool(false, types.NewTestMetadata()),
								LogDisconnections:               types.Bool(false, types.NewTestMetadata()),
								LogLockWaits:                    types.Bool(false, types.NewTestMetadata()),
								LogMinMessages:                  types.String("", types.NewTestMetadata()),
								LogTempFileSize:                 types.Int(-1, types.NewTestMetadata()),
							},
							IPConfiguration: sql.IPConfiguration{
								Metadata:   types.NewTestMetadata(),
								RequireTLS: types.Bool(true, types.NewTestMetadata()),
								EnableIPv4: types.Bool(false, types.NewTestMetadata()),
								AuthorizedNetworks: []struct {
									Name types.StringValue
									CIDR types.StringValue
								}{
									{
										Name: types.String("internal", types.NewTestMetadata()),
										CIDR: types.String("108.12.12.0/24", types.NewTestMetadata()),
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
					Metadata:        types.NewTestMetadata(),
					DatabaseVersion: types.String("POSTGRES_11", types.NewTestMetadata()),
					IsReplica:       types.Bool(false, types.NewTestMetadata()),
					Settings: sql.Settings{
						Backups: sql.Backups{
							Enabled: types.Bool(true, types.NewTestMetadata()),
						},
						Flags: sql.Flags{
							LogConnections:                  types.Bool(true, types.NewTestMetadata()),
							LogTempFileSize:                 types.Int(0, types.NewTestMetadata()),
							LogCheckpoints:                  types.Bool(true, types.NewTestMetadata()),
							LogDisconnections:               types.Bool(true, types.NewTestMetadata()),
							LogLockWaits:                    types.Bool(true, types.NewTestMetadata()),
							ContainedDatabaseAuthentication: types.Bool(true, types.NewTestMetadata()),
							CrossDBOwnershipChaining:        types.Bool(true, types.NewTestMetadata()),
							LocalInFile:                     types.Bool(false, types.NewTestMetadata()),
							LogMinDurationStatement:         types.Int(-1, types.NewTestMetadata()),
							LogMinMessages:                  types.String("", types.NewTestMetadata()),
						},
						IPConfiguration: sql.IPConfiguration{
							EnableIPv4: types.Bool(false, types.NewTestMetadata()),
							RequireTLS: types.Bool(true, types.NewTestMetadata()),
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
