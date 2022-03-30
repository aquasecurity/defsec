package compute

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/compute"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckVmDiskEncryptionCustomerKey(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Instance disk missing encryption key link",
			input: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: types.NewTestMetadata(),
						BootDisks: []compute.Disk{
							{
								Metadata: types.NewTestMetadata(),
								Encryption: compute.DiskEncryption{
									Metadata:   types.NewTestMetadata(),
									KMSKeyLink: types.String("", types.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance disk encryption key link provided",
			input: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: types.NewTestMetadata(),
						AttachedDisks: []compute.Disk{
							{
								Metadata: types.NewTestMetadata(),
								Encryption: compute.DiskEncryption{
									Metadata:   types.NewTestMetadata(),
									KMSKeyLink: types.String("kms-key-link", types.NewTestMetadata()),
								},
							},
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
			results := CheckVmDiskEncryptionCustomerKey.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckVmDiskEncryptionCustomerKey.Rule().LongID() {
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
