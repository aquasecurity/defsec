package athena

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/athena"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptDatabase(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  athena.Database
	}{
		{
			name: "athena database",
			terraform: `
			resource "aws_athena_database" "my_wg" {
				name   = "database_name"
			  
				encryption_configuration {
				   encryption_option = "SSE_KMS"
			   }
			}
`,
			expected: athena.Database{
				Metadata: types2.NewTestMetadata(),
				Name:     types2.String("database_name", types2.NewTestMetadata()),
				Encryption: athena.EncryptionConfiguration{
					Metadata: types2.NewTestMetadata(),
					Type:     types2.String(athena.EncryptionTypeSSEKMS, types2.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptDatabase(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptWorkgroup(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  athena.Workgroup
	}{
		{
			name: "encryption type SSE KMS",
			terraform: `
			resource "aws_athena_workgroup" "my_wg" {
				name = "example"
			  
				configuration {
				  enforce_workgroup_configuration    = true
			  
				  result_configuration {
					encryption_configuration {
					  encryption_option = "SSE_KMS"
					}
				  }
				}
			  }
`,
			expected: athena.Workgroup{
				Metadata: types2.NewTestMetadata(),
				Name:     types2.String("example", types2.NewTestMetadata()),
				Encryption: athena.EncryptionConfiguration{
					Metadata: types2.NewTestMetadata(),
					Type:     types2.String(athena.EncryptionTypeSSEKMS, types2.NewTestMetadata()),
				},
				EnforceConfiguration: types2.Bool(true, types2.NewTestMetadata()),
			},
		},
		{
			name: "configuration not enforced",
			terraform: `
			resource "aws_athena_workgroup" "my_wg" {
				name = "example"
			  
				configuration {
				  enforce_workgroup_configuration    = false
			  
				  result_configuration {
					encryption_configuration {
					  encryption_option = "SSE_KMS"
					}
				  }
				}
			}
`,
			expected: athena.Workgroup{
				Metadata: types2.NewTestMetadata(),
				Name:     types2.String("example", types2.NewTestMetadata()),
				Encryption: athena.EncryptionConfiguration{
					Metadata: types2.NewTestMetadata(),
					Type:     types2.String(athena.EncryptionTypeSSEKMS, types2.NewTestMetadata()),
				},
				EnforceConfiguration: types2.Bool(false, types2.NewTestMetadata()),
			},
		},
		{
			name: "enforce configuration defaults to true",
			terraform: `
			resource "aws_athena_workgroup" "my_wg" {
				name = "example"
			  
				configuration {
					result_configuration {
						encryption_configuration {
						  encryption_option = ""
						}
					}
				}
			}
`,
			expected: athena.Workgroup{
				Metadata: types2.NewTestMetadata(),
				Name:     types2.String("example", types2.NewTestMetadata()),
				Encryption: athena.EncryptionConfiguration{
					Metadata: types2.NewTestMetadata(),
					Type:     types2.String(athena.EncryptionTypeNone, types2.NewTestMetadata()),
				},
				EnforceConfiguration: types2.Bool(true, types2.NewTestMetadata()),
			},
		},
		{
			name: "missing configuration block",
			terraform: `
			resource "aws_athena_workgroup" "my_wg" {
				name = "example"
			}
`,
			expected: athena.Workgroup{
				Metadata: types2.NewTestMetadata(),
				Name:     types2.String("example", types2.NewTestMetadata()),
				Encryption: athena.EncryptionConfiguration{
					Metadata: types2.NewTestMetadata(),
					Type:     types2.String(athena.EncryptionTypeNone, types2.NewTestMetadata()),
				},
				EnforceConfiguration: types2.Bool(false, types2.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptWorkgroup(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_athena_database" "good_example" {
		name   = "database_name"
		bucket = aws_s3_bucket.hoge.bucket
	  
		encryption_configuration {
		   encryption_option = "SSE_KMS"
		   kms_key_arn       = aws_kms_key.example.arn
	   }
	  }
	  
	  resource "aws_athena_workgroup" "good_example" {
		name = "example"
	  
		configuration {
		  enforce_workgroup_configuration    = true
		  publish_cloudwatch_metrics_enabled = true
	  
		  result_configuration {
			output_location = "s3://${aws_s3_bucket.example.bucket}/output/"
	  
			encryption_configuration {
			  encryption_option = "SSE_KMS"
			  kms_key_arn       = aws_kms_key.example.arn
			}
		  }
		}
	  }`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Databases, 1)
	require.Len(t, adapted.Workgroups, 1)

	assert.Equal(t, 7, adapted.Databases[0].Encryption.Type.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, adapted.Databases[0].Encryption.Type.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 16, adapted.Workgroups[0].EnforceConfiguration.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 16, adapted.Workgroups[0].EnforceConfiguration.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 23, adapted.Workgroups[0].Encryption.Type.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 23, adapted.Workgroups[0].Encryption.Type.GetMetadata().Range().GetEndLine())
}
