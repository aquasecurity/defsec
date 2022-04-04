package ecr

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ecr"
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/liamg/iamgo"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptRepository(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  ecr.Repository
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_kms_key" "ecr_kms" {
				enable_key_rotation = true
			}
			
			resource "aws_ecr_repository" "foo" {
				name                 = "bar"
				image_tag_mutability = "MUTABLE"
			  
				image_scanning_configuration {
				  scan_on_push = true
				}
			
				encryption_configuration {
					encryption_type = "KMS"
					kms_key = aws_kms_key.ecr_kms.key_id
				}
			  }

			  resource "aws_ecr_repository_policy" "foopolicy" {
				repository = aws_ecr_repository.foo.name
			  
				policy = <<EOF
			  {
				  "Version": "2008-10-17",
				  "Statement": [
					  {
						  "Sid": "new policy",
						  "Effect": "Allow",
						  "Principal": "*",
						  "Action": [
							  "ecr:GetDownloadUrlForLayer",
							  "ecr:BatchGetImage",
							  "ecr:BatchCheckLayerAvailability",
							  "ecr:PutImage",
							  "ecr:InitiateLayerUpload",
							  "ecr:UploadLayerPart",
							  "ecr:CompleteLayerUpload",
							  "ecr:DescribeRepositories",
							  "ecr:GetRepositoryPolicy",
							  "ecr:ListImages",
							  "ecr:DeleteRepository",
							  "ecr:BatchDeleteImage",
							  "ecr:SetRepositoryPolicy",
							  "ecr:DeleteRepositoryPolicy"
						  ]
					  }
				  ]
			  }
			  EOF
			  }
`,
			expected: ecr.Repository{
				Metadata:           types.NewTestMetadata(),
				ImageTagsImmutable: types.Bool(false, types.NewTestMetadata()),
				ImageScanning: ecr.ImageScanning{
					Metadata:   types.NewTestMetadata(),
					ScanOnPush: types.Bool(true, types.NewTestMetadata()),
				},
				Encryption: ecr.Encryption{
					Metadata: types.NewTestMetadata(),
					Type:     types.String("KMS", types.NewTestMetadata()),
					KMSKeyID: types.String("aws_kms_key.ecr_kms", types.NewTestMetadata()),
				},
				Policies: []iam.Policy{
					{
						Metadata: types.NewTestMetadata(),
						Document: func() iam.Document {

							builder := iamgo.NewPolicyBuilder()
							builder.WithVersion("2008-10-17")

							sb := iamgo.NewStatementBuilder()
							sb.WithSid("new policy")
							sb.WithEffect(iamgo.EffectAllow)
							sb.WithActions([]string{
								"ecr:GetDownloadUrlForLayer",
								"ecr:BatchGetImage",
								"ecr:BatchCheckLayerAvailability",
								"ecr:PutImage",
								"ecr:InitiateLayerUpload",
								"ecr:UploadLayerPart",
								"ecr:CompleteLayerUpload",
								"ecr:DescribeRepositories",
								"ecr:GetRepositoryPolicy",
								"ecr:ListImages",
								"ecr:DeleteRepository",
								"ecr:BatchDeleteImage",
								"ecr:SetRepositoryPolicy",
								"ecr:DeleteRepositoryPolicy",
							})
							sb.WithAllPrincipals(true)
							builder.WithStatement(sb.Build())

							return iam.Document{
								Parsed:   builder.Build(),
								Metadata: types.NewTestMetadata(),
							}
						}(),
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_ecr_repository" "foo" {
			}
`,
			expected: ecr.Repository{
				Metadata:           types.NewTestMetadata(),
				ImageTagsImmutable: types.Bool(false, types.NewTestMetadata()),
				ImageScanning: ecr.ImageScanning{
					Metadata:   types.NewTestMetadata(),
					ScanOnPush: types.Bool(false, types.NewTestMetadata()),
				},
				Encryption: ecr.Encryption{
					Metadata: types.NewTestMetadata(),
					Type:     types.String("AES256", types.NewTestMetadata()),
					KMSKeyID: types.String("", types.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptRepository(modules.GetBlocks()[0], modules[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_kms_key" "ecr_kms" {
		enable_key_rotation = true
	}
	
	resource "aws_ecr_repository" "foo" {
		name                 = "bar"
		image_tag_mutability = "MUTABLE"
	  
		image_scanning_configuration {
		  scan_on_push = true
		}
	
		encryption_configuration {
			encryption_type = "KMS"
			kms_key = aws_kms_key.ecr_kms.key_id
		}
	  }

	  resource "aws_ecr_repository_policy" "foopolicy" {
		repository = aws_ecr_repository.foo.name
	  
		policy = <<EOF
	  {
		  "Version": "2008-10-17",
		  "Statement": [
			  {
				  "Sid": "new policy",
				  "Effect": "Allow",
				  "Principal": "*",
				  "Action": [
					  "ecr:GetDownloadUrlForLayer",
					  "ecr:BatchGetImage",
					  "ecr:BatchCheckLayerAvailability",
					  "ecr:PutImage",
					  "ecr:InitiateLayerUpload",
					  "ecr:UploadLayerPart",
					  "ecr:CompleteLayerUpload",
					  "ecr:DescribeRepositories",
					  "ecr:GetRepositoryPolicy",
					  "ecr:ListImages",
					  "ecr:DeleteRepository",
					  "ecr:BatchDeleteImage",
					  "ecr:SetRepositoryPolicy",
					  "ecr:DeleteRepositoryPolicy"
				  ]
			  }
		  ]
	  }
	  EOF
	  }`

	module := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(module)

	require.Len(t, adapted.Repositories, 1)
	repo := adapted.Repositories[0]

	assert.Equal(t, 6, repo.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 18, repo.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 8, repo.ImageTagsImmutable.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 8, repo.ImageTagsImmutable.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, repo.ImageScanning.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 12, repo.ImageScanning.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, repo.ImageScanning.ScanOnPush.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, repo.ImageScanning.ScanOnPush.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 14, repo.Encryption.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 17, repo.Encryption.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 15, repo.Encryption.Type.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 15, repo.Encryption.Type.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 2, repo.Encryption.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, repo.Encryption.KMSKeyID.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 20, repo.Policies[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 51, repo.Policies[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 23, repo.Policies[0].Document.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 50, repo.Policies[0].Document.GetMetadata().Range().GetEndLine())
}
