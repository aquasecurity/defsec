package iam

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/liamg/iamgo"

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
				Roles: []iam.Role{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Policies: []iam.Policy{
							{
								Metadata: defsecTypes.NewTestMetadata(),
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
										Metadata: defsecTypes.NewTestMetadata(),
									}
								}(),
								Builtin: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Builtin IAM policy with wildcard resource",
			input: iam.IAM{
				Roles: []iam.Role{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Policies: []iam.Policy{
							{
								Metadata: defsecTypes.NewTestMetadata(),
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
										Metadata: defsecTypes.NewTestMetadata(),
									}
								}(),
								Builtin: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "IAM policy with wildcard action",
			input: iam.IAM{
				Policies: []iam.Policy{
					{
						Metadata: defsecTypes.NewTestMetadata(),
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
								Metadata: defsecTypes.NewTestMetadata(),
							}
						}(),
						Builtin: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "IAM policies without wildcards",
			input: iam.IAM{
				Policies: []iam.Policy{
					{
						Metadata: defsecTypes.NewTestMetadata(),
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
								Metadata: defsecTypes.NewTestMetadata(),
							}
						}(),
						Builtin: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					},
				},
				Roles: []iam.Role{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Policies: []iam.Policy{
							{
								Metadata: defsecTypes.NewTestMetadata(),
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
										Metadata: defsecTypes.NewTestMetadata(),
									}
								}(),
								Builtin: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "IAM policy with wildcard resource for cloudwatch log stream",
			input: iam.IAM{
				Policies: []iam.Policy{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Document: func() iam.Document {

							builder := iamgo.NewPolicyBuilder()
							builder.WithVersion("2012-10-17")

							sb := iamgo.NewStatementBuilder()
							sb.WithEffect(iamgo.EffectAllow)
							sb.WithActions([]string{"logs:CreateLogStream"})
							sb.WithResources([]string{"arn:aws:logs:us-west-2:123456789012:log-group:SampleLogGroupName:*"})
							sb.WithAWSPrincipals([]string{"arn:aws:iam::1234567890:root"})

							builder.WithStatement(sb.Build())

							return iam.Document{
								Parsed:   builder.Build(),
								Metadata: defsecTypes.NewTestMetadata(),
							}
						}(),
						Builtin: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					},
				},
				Roles: []iam.Role{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Policies: []iam.Policy{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Document: func() iam.Document {

									builder := iamgo.NewPolicyBuilder()
									builder.WithVersion("2012-10-17")

									sb := iamgo.NewStatementBuilder()
									sb.WithEffect(iamgo.EffectAllow)
									sb.WithActions([]string{"sts:AssumeRole"})
									sb.WithServicePrincipals([]string{"logs.amazonaws.com"})

									builder.WithStatement(sb.Build())

									return iam.Document{
										Parsed:   builder.Build(),
										Metadata: defsecTypes.NewTestMetadata(),
									}
								}(),
								Builtin: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "IAM policy with wildcard resource for cloudwatch log stream",
			input: iam.IAM{
				Policies: []iam.Policy{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Document: func() iam.Document {

							builder := iamgo.NewPolicyBuilder()
							builder.WithVersion("2012-10-17")

							sb := iamgo.NewStatementBuilder()
							sb.WithEffect(iamgo.EffectAllow)
							sb.WithActions([]string{"logs:CreateLogStream"})
							sb.WithResources([]string{"*"})
							sb.WithAWSPrincipals([]string{"arn:aws:iam::1234567890:root"})

							builder.WithStatement(sb.Build())

							return iam.Document{
								Parsed:   builder.Build(),
								Metadata: defsecTypes.NewTestMetadata(),
							}
						}(),
						Builtin: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					},
				},
				Roles: []iam.Role{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Policies: []iam.Policy{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Document: func() iam.Document {

									builder := iamgo.NewPolicyBuilder()
									builder.WithVersion("2012-10-17")

									sb := iamgo.NewStatementBuilder()
									sb.WithEffect(iamgo.EffectAllow)
									sb.WithActions([]string{"sts:AssumeRole"})
									sb.WithServicePrincipals([]string{"logs.amazonaws.com"})

									builder.WithStatement(sb.Build())

									return iam.Document{
										Parsed:   builder.Build(),
										Metadata: defsecTypes.NewTestMetadata(),
									}
								}(),
								Builtin: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.IAM = test.input
			results := CheckNoPolicyWildcards.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPolicyWildcards.Rule().LongID() {
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
