package kms

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/kms"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckAutoRotateKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    kms.KMS
		expected bool
	}{
		{
			name: "ENCRYPT_DECRYPT KMS Key with auto-rotation disabled",
			input: kms.KMS{
				Keys: []kms.Key{
					{
						Usage:           defsecTypes.String("ENCRYPT_DECRYPT", defsecTypes.NewTestMetadata()),
						RotationEnabled: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "ENCRYPT_DECRYPT KMS Key with auto-rotation enabled",
			input: kms.KMS{
				Keys: []kms.Key{
					{
						Usage:           defsecTypes.String("ENCRYPT_DECRYPT", defsecTypes.NewTestMetadata()),
						RotationEnabled: defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "SIGN_VERIFY KMS Key with auto-rotation disabled",
			input: kms.KMS{
				Keys: []kms.Key{
					{
						Usage:           defsecTypes.String(kms.KeyUsageSignAndVerify, defsecTypes.NewTestMetadata()),
						RotationEnabled: defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.KMS = test.input
			results := CheckAutoRotateKeys.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckAutoRotateKeys.Rule().LongID() {
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
