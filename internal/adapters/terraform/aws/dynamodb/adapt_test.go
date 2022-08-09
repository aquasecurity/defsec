package dynamodb

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/dynamodb"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptCluster(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  dynamodb.DAXCluster
	}{
		{
			name: "cluster",
			terraform: `
			resource "aws_dax_cluster" "example" {
				server_side_encryption {
					enabled = true
				}
			  }
`,
			expected: dynamodb.DAXCluster{
				Metadata: types2.NewTestMetadata(),
				ServerSideEncryption: dynamodb.ServerSideEncryption{
					Metadata: types2.NewTestMetadata(),
					Enabled:  types2.Bool(true, types2.NewTestMetadata()),
					KMSKeyID: types2.String("", types2.NewTestMetadata()),
				},
				PointInTimeRecovery: types2.Bool(false, types2.NewTestMetadata()),
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

func Test_adaptTable(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  dynamodb.Table
	}{
		{
			name: "table",
			terraform: `
			resource "aws_dynamodb_table" "example" {
				name             = "example"
			
				server_side_encryption {
					enabled     = true
					kms_key_arn = "key-string"
				}

				point_in_time_recovery {
					enabled = true
				}
			}
`,
			expected: dynamodb.Table{
				Metadata: types2.NewTestMetadata(),
				ServerSideEncryption: dynamodb.ServerSideEncryption{
					Metadata: types2.NewTestMetadata(),
					Enabled:  types2.Bool(true, types2.NewTestMetadata()),
					KMSKeyID: types2.String("key-string", types2.NewTestMetadata()),
				},
				PointInTimeRecovery: types2.Bool(true, types2.NewTestMetadata()),
			},
		},
		{
			name: "table no kms",
			terraform: `
			resource "aws_dax_cluster" "example" {
				server_side_encryption {
					enabled = true
				}
			  }
`,
			expected: dynamodb.Table{
				Metadata: types2.NewTestMetadata(),
				ServerSideEncryption: dynamodb.ServerSideEncryption{
					Metadata: types2.NewTestMetadata(),
					Enabled:  types2.Bool(true, types2.NewTestMetadata()),
					KMSKeyID: types2.String("alias/aws/dynamodb", types2.NewTestMetadata()),
				},
				PointInTimeRecovery: types2.Bool(false, types2.NewTestMetadata()),
			},
		},
		{
			name: "reference key",
			terraform: `
			resource "aws_dynamodb_table" "example" {
				name             = "example"
			
				server_side_encryption {
					enabled     = true
					kms_key_arn = aws_kms_key.a.arn
				}
			}

			resource "aws_kms_key" "a" {
			  }
`,
			expected: dynamodb.Table{
				Metadata: types2.NewTestMetadata(),
				ServerSideEncryption: dynamodb.ServerSideEncryption{
					Metadata: types2.NewTestMetadata(),
					Enabled:  types2.Bool(true, types2.NewTestMetadata()),
					KMSKeyID: types2.String("aws_kms_key.a", types2.NewTestMetadata()),
				},
				PointInTimeRecovery: types2.Bool(false, types2.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptTable(modules.GetBlocks()[0], modules[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_dynamodb_table" "example" {
		name             = "example"
	
		server_side_encryption {
			enabled     = true
			kms_key_arn = "key-string"
		}

		point_in_time_recovery {
			enabled = true
		}
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.DAXClusters, 0)
	require.Len(t, adapted.Tables, 1)
	table := adapted.Tables[0]

	assert.Equal(t, 2, table.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 13, table.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, table.ServerSideEncryption.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 8, table.ServerSideEncryption.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 6, table.ServerSideEncryption.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, table.ServerSideEncryption.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 7, table.ServerSideEncryption.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, table.ServerSideEncryption.KMSKeyID.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, table.PointInTimeRecovery.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, table.PointInTimeRecovery.GetMetadata().Range().GetEndLine())
}
