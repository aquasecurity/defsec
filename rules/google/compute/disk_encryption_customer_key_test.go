package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/google/compute"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckDiskEncryptionCustomerKey(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Disk missing KMS key link",
			input: compute.Compute{
				Metadata: types.NewTestMetadata(),
				Disks: []compute.Disk{
					{
						Metadata: types.NewTestMetadata(),
						Encryption: compute.DiskEncryption{
							Metadata:   types.NewTestMetadata(),
							KMSKeyLink: types.String("", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Disk with KMS key link provided",
			input: compute.Compute{
				Metadata: types.NewTestMetadata(),
				Disks: []compute.Disk{
					{
						Metadata: types.NewTestMetadata(),
						Encryption: compute.DiskEncryption{
							Metadata:   types.NewTestMetadata(),
							KMSKeyLink: types.String("kms-key-link", types.NewTestMetadata()),
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
			testState.Google.Compute = test.input
			results := CheckDiskEncryptionCustomerKey.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == rules.StatusFailed && result.Rule().LongID() == CheckDiskEncryptionCustomerKey.Rule().LongID() {
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
