package documentdb

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/testutil"
	"github.com/aquasecurity/defsec/parsers/types"

	"github.com/aquasecurity/defsec/providers/aws/documentdb"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptCluster(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  documentdb.Cluster
	}{
		{
			name: "configured",
			terraform: `		
			resource "aws_docdb_cluster" "docdb" {
			  cluster_identifier      = "my-docdb-cluster"
			  kms_key_id 			  = "kms-key"
			  enabled_cloudwatch_logs_exports = "audit"
			  storage_encrypted = true
			}

			resource "aws_docdb_cluster_instance" "cluster_instances" {
				count              = 1
				identifier         = "my-docdb-cluster"
				cluster_identifier = aws_docdb_cluster.docdb.id
				kms_key_id 			  = "kms-key#1"
			  }
`,
			expected: documentdb.Cluster{
				Metadata:   types.NewTestMetadata(),
				Identifier: types.String("my-docdb-cluster", types.NewTestMetadata()),
				KMSKeyID:   types.String("kms-key", types.NewTestMetadata()),
				EnabledLogExports: []types.StringValue{
					types.String("audit", types.NewTestMetadata()),
				},
				Instances: []documentdb.Instance{
					{
						Metadata: types.NewTestMetadata(),
						KMSKeyID: types.String("kms-key#1", types.NewTestMetadata()),
					},
				},
				StorageEncrypted: types.Bool(true, types.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `		
			resource "aws_docdb_cluster" "docdb" {
			}
`,
			expected: documentdb.Cluster{
				Metadata:         types.NewTestMetadata(),
				Identifier:       types.String("", types.NewTestMetadata()),
				StorageEncrypted: types.Bool(false, types.NewTestMetadata()),
				KMSKeyID:         types.String("", types.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptCluster(modules.GetBlocks()[0], modules[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_docdb_cluster" "docdb" {
		cluster_identifier      = "my-docdb-cluster"
		kms_key_id 			  = "kms-key"
		enabled_cloudwatch_logs_exports = "audit"
		storage_encrypted = true
	}

 	resource "aws_docdb_cluster_instance" "cluster_instances" {
		count              	= 1
		identifier         	= "my-docdb-cluster"
		cluster_identifier 	= aws_docdb_cluster.docdb.id
		kms_key_id 		    = "kms-key"
	}`

	modules := testutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Clusters, 1)
	require.Len(t, adapted.Clusters[0].Instances, 1)

	cluster := adapted.Clusters[0]
	instance := cluster.Instances[0]

	assert.Equal(t, 2, cluster.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, cluster.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 3, cluster.Identifier.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, cluster.Identifier.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, cluster.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, cluster.KMSKeyID.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, cluster.EnabledLogExports[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, cluster.EnabledLogExports[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 6, cluster.StorageEncrypted.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, cluster.StorageEncrypted.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 9, instance.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 14, instance.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 13, instance.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 13, instance.KMSKeyID.GetMetadata().Range().GetEndLine())
}
