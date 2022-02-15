package ecr

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/ecr"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/trivy-config-parsers/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    ecr.ECR
		expected bool
	}{
		{
			name: "ECR repository policy with wildcard principal",
			input: ecr.ECR{
				Metadata: types.NewTestMetadata(),
				Repositories: []ecr.Repository{
					{
						Metadata: types.NewTestMetadata(),
						Policies: []types.StringValue{
							types.String(`{
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
							}`, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "ECR repository policy with specific principal",
			input: ecr.ECR{
				Metadata: types.NewTestMetadata(),
				Repositories: []ecr.Repository{
					{
						Metadata: types.NewTestMetadata(),
						Policies: []types.StringValue{
							types.String(`{
								"Version": "2008-10-17",
								"Statement": [
									{
										"Sid": "new policy",
										"Effect": "Allow",
										"Principal": "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root",
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
							}`, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.ECR = test.input
			results := CheckNoPublicAccess.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckNoPublicAccess.Rule().LongID() {
					found = true
				}
			}
			if test.expected {
				assert.True(t, found, "Rule should have been found")
			} else {
				assert.False(t, found, "Rule should not have been found")
			}
		})
	}
}
