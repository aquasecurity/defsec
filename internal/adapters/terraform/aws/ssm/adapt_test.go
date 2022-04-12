package ssm

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ssm"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  ssm.SSM
	}{
		{
			name: "reference key",
			terraform: `
			resource "aws_kms_key" "secrets" {
				enable_key_rotation = true
			}
			
			resource "aws_secretsmanager_secret" "example" {
			  name       = "lambda_password"
			  kms_key_id = aws_kms_key.secrets.arn
			}
`,
			expected: ssm.SSM{
				Secrets: []ssm.Secret{
					{
						Metadata: types.NewTestMetadata(),
						KMSKeyID: types.String("aws_kms_key.secrets", types.NewTestMetadata()),
					},
				},
			},
		},
		{
			name: "string key",
			terraform: `
			resource "aws_secretsmanager_secret" "example" {
			  name       = "lambda_password"
			  kms_key_id = "key_id"
			}
`,
			expected: ssm.SSM{
				Secrets: []ssm.Secret{
					{
						Metadata: types.NewTestMetadata(),
						KMSKeyID: types.String("key_id", types.NewTestMetadata()),
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_secretsmanager_secret" "example" {
			}
`,
			expected: ssm.SSM{
				Secrets: []ssm.Secret{
					{
						Metadata: types.NewTestMetadata(),
						KMSKeyID: types.String("alias/aws/secretsmanager", types.NewTestMetadata()),
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
	resource "aws_kms_key" "secrets" {
		enable_key_rotation = true
	}
	
	resource "aws_secretsmanager_secret" "example" {
	  name       = "lambda_password"
	  kms_key_id = aws_kms_key.secrets.arn
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Secrets, 1)
	secret := adapted.Secrets[0]

	assert.Equal(t, 6, secret.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 9, secret.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 2, secret.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, secret.KMSKeyID.GetMetadata().Range().GetEndLine())

}
