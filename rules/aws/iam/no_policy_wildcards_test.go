package iam

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/iam"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/trivy-config-parsers/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckNoPolicyWildcards(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "IAM policy with wildcard resource",
			input: iam.IAM{
				Metadata: types.NewTestMetadata(),

				Roles: []iam.Role{
					{
						Metadata: types.NewTestMetadata(),
						Policies: []iam.Policy{
							{
								Metadata: types.NewTestMetadata(),
								Document: types.String(` {
									"Version": "2012-10-17",
									"Statement": [
										{
											"Sid": "ListYourObjects",
											"Effect": "Allow",
											"Action": "s3:ListBucket",
											"Resource": ["arn:aws:s3:::*"],
											"Principal": {
												"AWS": "arn:aws:iam::1234567890:root"
											}
										}
									]
								}`, types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "IAM policy with wildcard action",
			input: iam.IAM{
				Metadata: types.NewTestMetadata(),
				Policies: []iam.Policy{
					{
						Metadata: types.NewTestMetadata(),
						Document: types.String(` {
							"Version": "2012-10-17",
							"Statement": [
								{
									"Sid": "ListYourObjects",
									"Effect": "Allow",
									"Action": "s3:*",
									"Resource": ["arn:aws:s3:::bucket-name"],
									"Principal": {
										"AWS": "arn:aws:iam::1234567890:root"
									}
								}
							]
						}`, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "IAM policies without wildcards",
			input: iam.IAM{
				Metadata: types.NewTestMetadata(),
				Policies: []iam.Policy{
					{
						Metadata: types.NewTestMetadata(),
						Document: types.String(`{
						statement {
							principals {
							  type        = "AWS"
							  identifiers = ["arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"]
							}
							actions   = ["s3:GetObject"]
							resources = [aws_s3_bucket.example.arn]
						  }
						}`, types.NewTestMetadata()),
					},
				},
				Roles: []iam.Role{
					{
						Metadata: types.NewTestMetadata(),
						Policies: []iam.Policy{
							{
								Metadata: types.NewTestMetadata(),
								Document: types.String(`{
									Version = "2012-10-17"
									Statement = [
									{
										Action = "sts:AssumeRole"
										Effect = "Allow"
										Sid    = ""
										Principal = {
										Service = "s3.amazonaws.com"
										}
									},
									]
								}`, types.NewTestMetadata()),
							},
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
			testState.AWS.IAM = test.input
			results := CheckNoPolicyWildcards.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckNoPolicyWildcards.Rule().LongID() {
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
