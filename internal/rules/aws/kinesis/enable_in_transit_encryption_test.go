package kinesis

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/kinesis"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableInTransitEncryption(t *testing.T) {
	tests := []struct {
		name     string
		input    kinesis.Kinesis
		expected bool
	}{
		{
			name: "AWS Kinesis Stream with no encryption",
			input: kinesis.Kinesis{
				Streams: []kinesis.Stream{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Encryption: kinesis.Encryption{
							Metadata: defsecTypes.NewTestMetadata(),
							Type:     defsecTypes.String("NONE", defsecTypes.NewTestMetadata()),
							KMSKeyID: defsecTypes.String("some-key", defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS Kinesis Stream with KMS encryption but no key",
			input: kinesis.Kinesis{
				Streams: []kinesis.Stream{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Encryption: kinesis.Encryption{
							Metadata: defsecTypes.NewTestMetadata(),
							Type:     defsecTypes.String(kinesis.EncryptionTypeKMS, defsecTypes.NewTestMetadata()),
							KMSKeyID: defsecTypes.String("", defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS Kinesis Stream with KMS encryption and key",
			input: kinesis.Kinesis{
				Streams: []kinesis.Stream{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Encryption: kinesis.Encryption{
							Metadata: defsecTypes.NewTestMetadata(),
							Type:     defsecTypes.String(kinesis.EncryptionTypeKMS, defsecTypes.NewTestMetadata()),
							KMSKeyID: defsecTypes.String("some-key", defsecTypes.NewTestMetadata()),
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
			testState.AWS.Kinesis = test.input
			results := CheckEnableInTransitEncryption.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableInTransitEncryption.Rule().LongID() {
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
