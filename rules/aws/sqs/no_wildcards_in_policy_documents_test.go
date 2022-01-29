package sqs

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/sqs"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/defsec/types"
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
						Policies: []types.StringValue{
							types.String(`
							{
							  "Statement": [
								{
								  "Effect": "Allow",
								  "Action": "sqs:*"
								}
							  ]
							}
							`, types.NewTestMetadata()),
						},
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
						Policies: []types.StringValue{
							types.String(`
							{
							  "Statement": [
								{
								  "Effect": "Allow",
								  "Principal": "*",
								  "Action": ["sqs:SendMessage", "sqs:ReceiveMessage"]
								}
							  ]
							}
							`, types.NewTestMetadata()),
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
