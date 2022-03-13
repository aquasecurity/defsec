package dynamodb

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/testutil"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/providers/aws/dynamodb"
)

func Test_adaptCluster(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  dynamodb.DAXCluster
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
			expected: dynamodb.DAXCluster{
				Metadata: types.NewTestMetadata(),
				ServerSideEncryption: dynamodb.ServerSideEncryption{
					Metadata: types.NewTestMetadata(),
					Enabled:  types.Bool(true, types.NewTestMetadata()),
					KMSKeyID: types.String("key-string", types.NewTestMetadata()),
				},
				PointInTimeRecovery: types.Bool(true, types.NewTestMetadata()),
			},
		},
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
				Metadata: types.NewTestMetadata(),
				ServerSideEncryption: dynamodb.ServerSideEncryption{
					Metadata: types.NewTestMetadata(),
					Enabled:  types.Bool(true, types.NewTestMetadata()),
					KMSKeyID: types.String("", types.NewTestMetadata()),
				},
				PointInTimeRecovery: types.Bool(false, types.NewTestMetadata()),
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
			expected: dynamodb.DAXCluster{
				Metadata: types.NewTestMetadata(),
				ServerSideEncryption: dynamodb.ServerSideEncryption{
					Metadata: types.NewTestMetadata(),
					Enabled:  types.Bool(true, types.NewTestMetadata()),
					KMSKeyID: types.String("aws_kms_key.a", types.NewTestMetadata()),
				},
				PointInTimeRecovery: types.Bool(false, types.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptCluster(modules.GetBlocks()[0], modules[0])
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

	modules := testutil.CreateModulesFromSource(src, ".tf", t)
	adapted := Adapt(modules)

	require.Len(t, adapted.DAXClusters, 1)
	table := adapted.DAXClusters[0]

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
