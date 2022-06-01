package sqs

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/sqs"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableQueueEncryption(t *testing.T) {
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
						Metadata: types.NewTestMetadata(),
						Encryption: sqs.Encryption{
							Metadata:          types.NewTestMetadata(),
							ManagedEncryption: types.Bool(false, types.NewTestMetadata()),
							KMSKeyID:          types.String("", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "SQS Queue encrypted with default key",
			input: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: types.NewTestMetadata(),
						Encryption: sqs.Encryption{
							Metadata:          types.NewTestMetadata(),
							ManagedEncryption: types.Bool(false, types.NewTestMetadata()),
							KMSKeyID:          types.String("alias/aws/sqs", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "SQS Queue encrypted with proper key",
			input: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: types.NewTestMetadata(),
						Encryption: sqs.Encryption{
							Metadata:          types.NewTestMetadata(),
							ManagedEncryption: types.Bool(false, types.NewTestMetadata()),
							KMSKeyID:          types.String("some-ok-key", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "SQS Queue encrypted with proper key",
			input: sqs.SQS{
				Queues: []sqs.Queue{
					{
						Metadata: types.NewTestMetadata(),
						Encryption: sqs.Encryption{
							Metadata:          types.NewTestMetadata(),
							ManagedEncryption: types.Bool(true, types.NewTestMetadata()),
							KMSKeyID:          types.String("", types.NewTestMetadata()),
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
			results := CheckEnableQueueEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableQueueEncryption.Rule().LongID() {
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
