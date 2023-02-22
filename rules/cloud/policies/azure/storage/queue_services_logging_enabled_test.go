package storage

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/storage"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckQueueServicesLoggingEnabled(t *testing.T) {
	tests := []struct {
		name     string
		input    storage.Storage
		expected bool
	}{
		{
			name: "Storage account queue properties logging disabled",
			input: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						QueueProperties: storage.QueueProperties{
							Metadata:      defsecTypes.NewTestMetadata(),
							EnableLogging: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},
						Queues: []storage.Queue{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Name:     defsecTypes.String("my-queue", defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Storage account queue properties logging disabled with no queues",
			input: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						QueueProperties: storage.QueueProperties{
							Metadata:      defsecTypes.NewTestMetadata(),
							EnableLogging: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "Storage account queue properties logging enabled",
			input: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						QueueProperties: storage.QueueProperties{
							Metadata:      defsecTypes.NewTestMetadata(),
							EnableLogging: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
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
			testState.Azure.Storage = test.input
			results := CheckQueueServicesLoggingEnabled.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckQueueServicesLoggingEnabled.Rule().LongID() {
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
