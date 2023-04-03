package iam

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/liamg/iamgo"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestFilterIamPassRole(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "policy have iam:PassRole",
			input: iam.IAM{
				Policies: []iam.Policy{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Name:     defsecTypes.String("new_Policy_with_iam_pass_role", defsecTypes.NewTestMetadata()),
						Document: func() iam.Document {

							builder := iamgo.NewPolicyBuilder()
							builder.WithVersion("2012-10-17")

							sb := iamgo.NewStatementBuilder()
							sb.WithSid("ListYourObjects")
							sb.WithEffect(iamgo.EffectAllow)
							sb.WithActions([]string{"iam:PassRole"})
							sb.WithAWSPrincipals([]string{"arn:aws:iam::1234567890:root"})

							builder.WithStatement(sb.Build())

							return iam.Document{
								Parsed:   builder.Build(),
								Metadata: defsecTypes.NewTestMetadata(),
							}
						}(),
					},
				},
			},
			expected: false,
		},
		{
			name: "policy does not have iam:PassRole",
			input: iam.IAM{
				Policies: []iam.Policy{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Name:     defsecTypes.String("newPolicy", defsecTypes.NewTestMetadata()),
						Document: func() iam.Document {

							builder := iamgo.NewPolicyBuilder()
							builder.WithVersion("2012-10-17")

							sb := iamgo.NewStatementBuilder()
							sb.WithSid("ListYourObjects")
							sb.WithEffect(iamgo.EffectAllow)
							sb.WithActions([]string{"s3:GetObject"})
							sb.WithAWSPrincipals([]string{"arn:aws:iam::1234567890:root"})

							builder.WithStatement(sb.Build())

							return iam.Document{
								Parsed:   builder.Build(),
								Metadata: defsecTypes.NewTestMetadata(),
							}
						}(),
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
			results := FilterIamPassRole.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == FilterIamPassRole.Rule().LongID() {
					found = true
				}
			}
			if test.expected {
				assert.False(t, found, "Rule should have been found")
			} else {
				assert.True(t, found, "Rule should not have been found")
			}
		})
	}
}
