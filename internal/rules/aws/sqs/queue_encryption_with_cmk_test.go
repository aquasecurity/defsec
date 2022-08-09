package sqs

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/sqs"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckQueueEncryptionUsesCMK(t *testing.T) {
	tests := []struct {
		name     string
		input    sqs.SQS
		expected bool
	}{
		{
			name: "SQS Queue unencrypted",
			input: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Encryption: sqs.Encryption{
							Metadata: defsecTypes.NewTestMetadata(),
							KMSKeyID: defsecTypes.String("", defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "SQS Queue encrypted with default key",
			input: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Encryption: sqs.Encryption{
							Metadata: defsecTypes.NewTestMetadata(),
							KMSKeyID: defsecTypes.String("alias/aws/sqs", defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "SQS Queue encrypted with proper key",
			input: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Encryption: sqs.Encryption{
							Metadata: defsecTypes.NewTestMetadata(),
							KMSKeyID: defsecTypes.String("some-ok-key", defsecTypes.NewTestMetadata()),
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
			results := CheckQueueEncryptionUsesCMK.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckQueueEncryptionUsesCMK.Rule().LongID() {
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
