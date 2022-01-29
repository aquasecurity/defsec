package sns

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/sns"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/defsec/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckEnableTopicEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    sns.SNS
		expected bool
	}{
		{
			name: "AWS SNS Topic without encryption",
			input: sns.SNS{
				Metadata: types.NewTestMetadata(),
				Topics: []sns.Topic{
					{
						Metadata: types.NewTestMetadata(),
						Encryption: sns.Encryption{
							Metadata: types.NewTestMetadata(),
							KMSKeyID: types.String("", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS SNS Topic encrypted with default key",
			input: sns.SNS{
				Metadata: types.NewTestMetadata(),
				Topics: []sns.Topic{
					{
						Metadata: types.NewTestMetadata(),
						Encryption: sns.Encryption{
							Metadata: types.NewTestMetadata(),
							KMSKeyID: types.String("alias/aws/sns", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS SNS Topic properly encrypted",
			input: sns.SNS{
				Metadata: types.NewTestMetadata(),
				Topics: []sns.Topic{
					{
						Metadata: types.NewTestMetadata(),
						Encryption: sns.Encryption{
							Metadata: types.NewTestMetadata(),
							KMSKeyID: types.String("some-ok-key", types.NewTestMetadata()),
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
			testState.AWS.SNS = test.input
			results := CheckEnableTopicEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckEnableTopicEncryption.Rule().LongID() {
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
