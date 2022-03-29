package iam

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/liamg/iamgo"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnforceMFA(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "IAM policy with no MFA required",
			input: iam.IAM{
				Metadata: types.NewTestMetadata(),
				Groups: []iam.Group{
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
									sb.WithActions([]string{"ec2:*"})

									builder.WithStatement(sb.Build())

									return iam.Document{
										Parsed: builder.Build(),
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
			name: "IAM policy with MFA required",
			input: iam.IAM{
				Metadata: types.NewTestMetadata(),
				Groups: []iam.Group{
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
									sb.WithActions([]string{"ec2:*"})
									sb.WithCondition("Bool", "aws:MultiFactorAuthPresent", []string{"true"})

									builder.WithStatement(sb.Build())

									return iam.Document{
										Parsed: builder.Build(),
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
			results := CheckEnforceMFA.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnforceMFA.Rule().LongID() {
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
