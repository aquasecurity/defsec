package iam

import (
	"testing"

	"github.com/liamg/iamgo"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/provider/aws/iam"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
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
								Document: func() iam.Document {

									builder := iamgo.NewPolicyBuilder()
									builder.WithVersion("2012-10-17")

									sb := iamgo.NewStatementBuilder()
									sb.WithSid("ListYourObjects")
									sb.WithEffect(iamgo.EffectAllow)
									sb.WithActions([]string{"s3:ListBucket"})
									sb.WithResources([]string{"arn:aws:s3:::*"})
									sb.WithAWSPrincipals([]string{"arn:aws:iam::1234567890:root"})

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
						Document: func() iam.Document {

							builder := iamgo.NewPolicyBuilder()
							builder.WithVersion("2012-10-17")

							sb := iamgo.NewStatementBuilder()
							sb.WithSid("ListYourObjects")
							sb.WithEffect(iamgo.EffectAllow)
							sb.WithActions([]string{"s3:*"})
							sb.WithResources([]string{"arn:aws:s3:::bucket-name"})
							sb.WithAWSPrincipals([]string{"arn:aws:iam::1234567890:root"})

							builder.WithStatement(sb.Build())

							return iam.Document{
								Parsed:   builder.Build(),
								Metadata: types.NewTestMetadata(),
							}
						}(),
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
						Document: func() iam.Document {

							builder := iamgo.NewPolicyBuilder()
							builder.WithVersion("2012-10-17")

							sb := iamgo.NewStatementBuilder()
							sb.WithEffect(iamgo.EffectAllow)
							sb.WithActions([]string{"s3:GetObject"})
							sb.WithResources([]string{"arn:aws:s3:::bucket-name"})
							sb.WithAWSPrincipals([]string{"arn:aws:iam::1234567890:root"})

							builder.WithStatement(sb.Build())

							return iam.Document{
								Parsed:   builder.Build(),
								Metadata: types.NewTestMetadata(),
							}
						}(),
					},
				},
				Roles: []iam.Role{
					{
						Metadata: types.NewTestMetadata(),
						Policies: []iam.Policy{
							{
								Metadata: types.NewTestMetadata(),
								Document: func() iam.Document {

									builder := iamgo.NewPolicyBuilder()
									builder.WithVersion("2012-10-17")

									sb := iamgo.NewStatementBuilder()
									sb.WithEffect(iamgo.EffectAllow)
									sb.WithActions([]string{"sts:AssumeRole"})
									sb.WithServicePrincipals([]string{"s3.amazonaws.com"})

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
