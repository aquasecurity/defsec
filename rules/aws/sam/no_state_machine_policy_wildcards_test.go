package sam

import (
	"testing"

	"github.com/aquasecurity/defsec/providers/aws/iam"
	"github.com/liamg/iamgo"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/sam"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckNoStateMachinePolicyWildcards(t *testing.T) {
	tests := []struct {
		name     string
		input    sam.SAM
		expected bool
	}{
		{
			name: "Wildcard action in state machine policy",
			input: sam.SAM{
				Metadata: types.NewTestMetadata(),
				StateMachines: []sam.StateMachine{
					{
						Metadata: types.NewTestMetadata(),
						Policies: func() []iam.Policy {

							sb := iamgo.NewStatementBuilder()
							sb.WithSid("new policy")
							sb.WithEffect("Allow")
							sb.WithActions([]string{
								"s3:GetObject",
							})
							sb.WithResources([]string{"arn:aws:s3:::my-bucket/*"})
							sb.WithAWSPrincipals([]string{"*"})

							builder := iamgo.NewPolicyBuilder()
							builder.WithVersion("2012-10-17")
							builder.WithStatement(sb.Build())

							return []iam.Policy{
								{
									Document: iam.Document{
										Metadata: types.NewTestMetadata(),
										Parsed:   builder.Build(),
									},
								},
							}
						}(),
					},
				},
			},
			expected: true,
		},
		{
			name: "Specific action in state machine policy",
			input: sam.SAM{
				Metadata: types.NewTestMetadata(),
				StateMachines: []sam.StateMachine{
					{
						Metadata: types.NewTestMetadata(),
						Policies: func() []iam.Policy {

							sb := iamgo.NewStatementBuilder()
							sb.WithSid("new policy")
							sb.WithEffect("Allow")
							sb.WithActions([]string{
								"s3:GetObject",
							})
							sb.WithResources([]string{"arn:aws:s3:::my-bucket/*"})
							sb.WithAWSPrincipals([]string{"proper-value"})

							builder := iamgo.NewPolicyBuilder()
							builder.WithVersion("2012-10-17")
							builder.WithStatement(sb.Build())

							return []iam.Policy{
								{
									Document: iam.Document{
										Metadata: types.NewTestMetadata(),
										Parsed:   builder.Build(),
									},
								},
							}
						}(),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.SAM = test.input
			results := CheckNoStateMachinePolicyWildcards.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == rules.StatusFailed && result.Rule().LongID() == CheckNoStateMachinePolicyWildcards.Rule().LongID() {
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
