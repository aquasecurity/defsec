package documentdb

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/documentdb"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
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
				Metadata:   types2.NewTestMetadata(),
				Identifier: types2.String("my-docdb-cluster", types2.NewTestMetadata()),
				KMSKeyID:   types2.String("kms-key", types2.NewTestMetadata()),
				EnabledLogExports: []types2.StringValue{
					types2.String("audit", types2.NewTestMetadata()),
				},
				Instances: []documentdb.Instance{
					{
						Metadata: types2.NewTestMetadata(),
						KMSKeyID: types2.String("kms-key#1", types2.NewTestMetadata()),
					},
				},
				StorageEncrypted: types2.Bool(true, types2.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `		
			resource "aws_docdb_cluster" "docdb" {
			}
`,
			expected: documentdb.Cluster{
				Metadata:         types2.NewTestMetadata(),
				Identifier:       types2.String("", types2.NewTestMetadata()),
				StorageEncrypted: types2.Bool(false, types2.NewTestMetadata()),
				KMSKeyID:         types2.String("", types2.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
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

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
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
