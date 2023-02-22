package compute

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/compute"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckDiskEncryptionRequired(t *testing.T) {
	tests := []struct {
		name     string
		input    compute.Compute
		expected bool
	}{
		{
			name: "Disk with plaintext encryption key",
			input: compute.Compute{
				Disks: []compute.Disk{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Encryption: compute.DiskEncryption{
							Metadata: defsecTypes.NewTestMetadata(),
							RawKey:   defsecTypes.Bytes([]byte("b2ggbm8gdGhpcyBpcyBiYWQ"), defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Instance disk with plaintext encryption key",
			input: compute.Compute{
				Instances: []compute.Instance{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						BootDisks: []compute.Disk{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Encryption: compute.DiskEncryption{
									Metadata: defsecTypes.NewTestMetadata(),
									RawKey:   defsecTypes.Bytes([]byte("b2ggbm8gdGhpcyBpcyBiYWQ"), defsecTypes.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Disks with no plaintext encryption keys",
			input: compute.Compute{
				Disks: []compute.Disk{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Encryption: compute.DiskEncryption{
							Metadata: defsecTypes.NewTestMetadata(),
							RawKey:   defsecTypes.Bytes([]byte(""), defsecTypes.NewTestMetadata()),
						},
					},
				},
				Instances: []compute.Instance{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						BootDisks: []compute.Disk{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Encryption: compute.DiskEncryption{
									Metadata: defsecTypes.NewTestMetadata(),
									RawKey:   defsecTypes.Bytes([]byte(""), defsecTypes.NewTestMetadata()),
								},
							},
						},
						AttachedDisks: []compute.Disk{
							{
								Metadata: defsecTypes.NewTestMetadata(),
								Encryption: compute.DiskEncryption{
									Metadata: defsecTypes.NewTestMetadata(),
									RawKey:   defsecTypes.Bytes([]byte(""), defsecTypes.NewTestMetadata()),
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
			results := CheckDiskEncryptionRequired.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckDiskEncryptionRequired.Rule().LongID() {
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
