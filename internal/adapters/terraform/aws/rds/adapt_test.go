package rds

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/pkg/providers/aws/rds"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/test/testutil"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  rds.RDS
	}{
		{
			name: "defined",
			terraform: `

			resource "aws_rds_cluster" "example" {
				engine                  = "aurora-mysql"
				backup_retention_period = 7
				kms_key_id  = "kms_key_1"
				storage_encrypted = true
				replication_source_identifier = "arn-of-a-source-db-cluster"
			  }
	
			resource "aws_rds_cluster_instance" "example" {
				cluster_identifier      = aws_rds_cluster.example.id
				name = "bar"
				performance_insights_enabled = true
				performance_insights_kms_key_id = "performance_key_0"
				kms_key_id  = "kms_key_0"
				storage_encrypted = true
			}

			resource "aws_db_security_group" "example" {
				# ...
			}

			resource "aws_db_instance" "example" {
				publicly_accessible = true
				backup_retention_period = 5
				skip_final_snapshot  = true
				performance_insights_enabled = true
				performance_insights_kms_key_id = "performance_key_1"
				storage_encrypted = true
				kms_key_id = "kms_key_2"
			}
`,
			expected: rds.RDS{
				Instances: []rds.Instance{
					{
						Metadata:                  types2.NewTestMetadata(),
						BackupRetentionPeriodDays: types2.Int(5, types2.NewTestMetadata()),
						ReplicationSourceARN:      types2.String("", types2.NewTestMetadata()),
						PerformanceInsights: rds.PerformanceInsights{
							Metadata: types2.NewTestMetadata(),
							Enabled:  types2.Bool(true, types2.NewTestMetadata()),
							KMSKeyID: types2.String("performance_key_1", types2.NewTestMetadata()),
						},
						Encryption: rds.Encryption{
							Metadata:       types2.NewTestMetadata(),
							EncryptStorage: types2.Bool(true, types2.NewTestMetadata()),
							KMSKeyID:       types2.String("kms_key_2", types2.NewTestMetadata()),
						},
						PublicAccess: types2.Bool(true, types2.NewTestMetadata()),
					},
				},
				Clusters: []rds.Cluster{
					{
						Metadata:                  types2.NewTestMetadata(),
						BackupRetentionPeriodDays: types2.Int(7, types2.NewTestMetadata()),
						ReplicationSourceARN:      types2.String("arn-of-a-source-db-cluster", types2.NewTestMetadata()),
						PerformanceInsights: rds.PerformanceInsights{
							Metadata: types2.NewTestMetadata(),
							Enabled:  types2.Bool(false, types2.NewTestMetadata()),
							KMSKeyID: types2.String("", types2.NewTestMetadata()),
						},
						Encryption: rds.Encryption{
							Metadata:       types2.NewTestMetadata(),
							EncryptStorage: types2.Bool(true, types2.NewTestMetadata()),
							KMSKeyID:       types2.String("kms_key_1", types2.NewTestMetadata()),
						},
						Instances: []rds.ClusterInstance{
							{
								Metadata: types2.NewTestMetadata(),
								Instance: rds.Instance{

									Metadata:                  types2.NewTestMetadata(),
									BackupRetentionPeriodDays: types2.Int(0, types2.NewTestMetadata()),
									ReplicationSourceARN:      types2.String("", types2.NewTestMetadata()),
									PerformanceInsights: rds.PerformanceInsights{
										Metadata: types2.NewTestMetadata(),
										Enabled:  types2.Bool(true, types2.NewTestMetadata()),
										KMSKeyID: types2.String("performance_key_0", types2.NewTestMetadata()),
									},
									Encryption: rds.Encryption{
										Metadata:       types2.NewTestMetadata(),
										EncryptStorage: types2.Bool(true, types2.NewTestMetadata()),
										KMSKeyID:       types2.String("kms_key_0", types2.NewTestMetadata()),
									},
									PublicAccess: types2.Bool(false, types2.NewTestMetadata()),
								},
								ClusterIdentifier: types2.String("aws_rds_cluster.example", types2.NewTestMetadata()),
							},
						},
						PublicAccess: types2.Bool(false, types2.NewTestMetadata()),
					},
				},
				Classic: rds.Classic{
					DBSecurityGroups: []rds.DBSecurityGroup{
						{
							Metadata: types2.NewTestMetadata(),
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

func Test_adaptInstance(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  rds.Instance
	}{
		{
			name: "instance defaults",
			terraform: `
			resource "aws_db_instance" "example" {
			}
`,
			expected: rds.Instance{
				Metadata:                  types2.NewTestMetadata(),
				BackupRetentionPeriodDays: types2.Int(0, types2.NewTestMetadata()),
				ReplicationSourceARN:      types2.String("", types2.NewTestMetadata()),
				PerformanceInsights: rds.PerformanceInsights{
					Metadata: types2.NewTestMetadata(),
					Enabled:  types2.Bool(false, types2.NewTestMetadata()),
					KMSKeyID: types2.String("", types2.NewTestMetadata()),
				},
				Encryption: rds.Encryption{
					Metadata:       types2.NewTestMetadata(),
					EncryptStorage: types2.Bool(false, types2.NewTestMetadata()),
					KMSKeyID:       types2.String("", types2.NewTestMetadata()),
				},
				PublicAccess: types2.Bool(false, types2.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptInstance(modules.GetBlocks()[0], modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptCluster(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  rds.Cluster
	}{
		{
			name: "cluster defaults",
			terraform: `
			resource "aws_rds_cluster" "example" {
			  }
`,
			expected: rds.Cluster{
				Metadata:                  types2.NewTestMetadata(),
				BackupRetentionPeriodDays: types2.Int(1, types2.NewTestMetadata()),
				ReplicationSourceARN:      types2.String("", types2.NewTestMetadata()),
				PerformanceInsights: rds.PerformanceInsights{
					Metadata: types2.NewTestMetadata(),
					Enabled:  types2.Bool(false, types2.NewTestMetadata()),
					KMSKeyID: types2.String("", types2.NewTestMetadata()),
				},
				Encryption: rds.Encryption{
					Metadata:       types2.NewTestMetadata(),
					EncryptStorage: types2.Bool(false, types2.NewTestMetadata()),
					KMSKeyID:       types2.String("", types2.NewTestMetadata()),
				},
				PublicAccess: types2.Bool(false, types2.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted, _ := adaptCluster(modules.GetBlocks()[0], modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_rds_cluster" "example" {
		backup_retention_period = 7
		kms_key_id  = "kms_key_1"
		storage_encrypted = true
		replication_source_identifier = "arn-of-a-source-db-cluster"
	  }
	
	resource "aws_rds_cluster_instance" "example" {
		cluster_identifier      = aws_rds_cluster.example.id
		backup_retention_period = 7
		performance_insights_enabled = true
		performance_insights_kms_key_id = "performance_key"
		storage_encrypted = true
		kms_key_id  = "kms_key_0"
	}

	resource "aws_db_security_group" "example" {
	}

	resource "aws_db_instance" "example" {
		publicly_accessible = false
		backup_retention_period = 7
		performance_insights_enabled = true
		performance_insights_kms_key_id = "performance_key"
		storage_encrypted = true
		kms_key_id  = "kms_key_0"
	}
`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Clusters, 1)
	require.Len(t, adapted.Instances, 1)

	cluster := adapted.Clusters[0]
	instance := adapted.Instances[0]
	classic := adapted.Classic

	assert.Equal(t, 2, cluster.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, cluster.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 3, cluster.BackupRetentionPeriodDays.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, cluster.BackupRetentionPeriodDays.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, cluster.Encryption.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, cluster.Encryption.KMSKeyID.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, cluster.Encryption.EncryptStorage.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, cluster.Encryption.EncryptStorage.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 6, cluster.ReplicationSourceARN.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, cluster.ReplicationSourceARN.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 9, cluster.Instances[0].Instance.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 16, cluster.Instances[0].Instance.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 2, cluster.Instances[0].ClusterIdentifier.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, cluster.Instances[0].ClusterIdentifier.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, cluster.Instances[0].Instance.BackupRetentionPeriodDays.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, cluster.Instances[0].Instance.BackupRetentionPeriodDays.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 12, cluster.Instances[0].Instance.PerformanceInsights.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 12, cluster.Instances[0].Instance.PerformanceInsights.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 13, cluster.Instances[0].Instance.PerformanceInsights.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 13, cluster.Instances[0].Instance.PerformanceInsights.KMSKeyID.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 14, cluster.Instances[0].Instance.Encryption.EncryptStorage.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 14, cluster.Instances[0].Instance.Encryption.EncryptStorage.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 15, cluster.Instances[0].Instance.Encryption.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 15, cluster.Instances[0].Instance.Encryption.KMSKeyID.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 18, classic.DBSecurityGroups[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 19, classic.DBSecurityGroups[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 21, instance.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 28, instance.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 22, instance.PublicAccess.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 22, instance.PublicAccess.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 23, instance.BackupRetentionPeriodDays.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 23, instance.BackupRetentionPeriodDays.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 24, instance.PerformanceInsights.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 24, instance.PerformanceInsights.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 25, instance.PerformanceInsights.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 25, instance.PerformanceInsights.KMSKeyID.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 26, instance.Encryption.EncryptStorage.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 26, instance.Encryption.EncryptStorage.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 27, instance.Encryption.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 27, instance.Encryption.KMSKeyID.GetMetadata().Range().GetEndLine())
}
