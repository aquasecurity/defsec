package sql

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/providers/google/sql"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
)

func Test_Adapt(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  sql.SQL
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: sql.SQL{},
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

func Test_adaptInstance(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  sql.DatabaseInstance
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: sql.DatabaseInstance{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptInstance(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptIPConfig(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name      string
		terraform string
		expected  sql.IPConfiguration
	}{
		{
			name: "basic",
			terraform: `
resource "" "example" {
    
}
`,
			expected: sql.IPConfiguration{},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptIPConfig(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}
