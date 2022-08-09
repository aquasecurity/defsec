package ec2

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEncryptionCustomerKey(t *testing.T) {
	tests := []struct {
		name     string
		input    ec2.EC2
		expected bool
	}{
		{
			name: "EC2 volume missing KMS key",
			input: ec2.EC2{
				Volumes: []ec2.Volume{
					{
						Metadata: types2.NewTestMetadata(),
						Encryption: ec2.Encryption{
							Metadata: types2.NewTestMetadata(),
							KMSKeyID: types2.String("", types2.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "EC2 volume encrypted with KMS key",
			input: ec2.EC2{
				Volumes: []ec2.Volume{
					{
						Metadata: types2.NewTestMetadata(),
						Encryption: ec2.Encryption{
							Metadata: types2.NewTestMetadata(),
							KMSKeyID: types2.String("some-kms-key", types2.NewTestMetadata()),
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
			testState.AWS.EC2 = test.input
			results := CheckEncryptionCustomerKey.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEncryptionCustomerKey.Rule().LongID() {
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
