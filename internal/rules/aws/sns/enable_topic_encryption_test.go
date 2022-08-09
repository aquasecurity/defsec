package sns

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/sns"
	"github.com/aquasecurity/defsec/pkg/scan"

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
				Topics: []sns.Topic{
					{
						Metadata: types2.NewTestMetadata(),
						Encryption: sns.Encryption{
							Metadata: types2.NewTestMetadata(),
							KMSKeyID: types2.String("", types2.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS SNS Topic encrypted with default key",
			input: sns.SNS{
				Topics: []sns.Topic{
					{
						Metadata: types2.NewTestMetadata(),
						Encryption: sns.Encryption{
							Metadata: types2.NewTestMetadata(),
							KMSKeyID: types2.String("alias/aws/sns", types2.NewTestMetadata()),
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "AWS SNS Topic properly encrypted",
			input: sns.SNS{
				Topics: []sns.Topic{
					{
						Metadata: types2.NewTestMetadata(),
						Encryption: sns.Encryption{
							Metadata: types2.NewTestMetadata(),
							KMSKeyID: types2.String("some-ok-key", types2.NewTestMetadata()),
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
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableTopicEncryption.Rule().LongID() {
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
