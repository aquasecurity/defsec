package sqs

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/iam"
	"github.com/liamg/iamgo"

	"github.com/aquasecurity/defsec/provider/aws/sqs"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/trivy-config-parsers/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckNoWildcardsInPolicyDocuments(t *testing.T) {
	tests := []struct {
		name     string
		input    sqs.SQS
		expected bool
	}{
		{
			name: "AWS SQS policy document with wildcard action statement",
			input: sqs.SQS{
				Metadata: types.NewTestMetadata(),
				Queues: []sqs.Queue{
					{
						Metadata: types.NewTestMetadata(),
						Policies: func() []iam.Policy {

							sb := iamgo.NewStatementBuilder()
							sb.WithSid("new policy")
							sb.WithEffect("Allow")
							sb.WithActions([]string{
								"sqs:*",
							})
							sb.WithResources([]string{"arn:aws:sqs:::my-queue"})

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
			name: "AWS SQS policy document with action statement list",
			input: sqs.SQS{
				Metadata: types.NewTestMetadata(),
				Queues: []sqs.Queue{
					{
						Metadata: types.NewTestMetadata(),
						Policies: func() []iam.Policy {

							sb := iamgo.NewStatementBuilder()
							sb.WithSid("new policy")
							sb.WithEffect("Allow")
							sb.WithActions([]string{
								"sqs:SendMessage",
								"sqs:ReceiveMessage",
							})
							sb.WithResources([]string{"arn:aws:sqs:::my-queue"})
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
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.SQS = test.input
			results := CheckNoWildcardsInPolicyDocuments.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckNoWildcardsInPolicyDocuments.Rule().LongID() {
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
