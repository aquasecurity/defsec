package kms

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/kms"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
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
				Metadata: types.NewTestMetadata(),
				Keys: []kms.Key{
					{
						Usage:           types.String("ENCRYPT_DECRYPT", types.NewTestMetadata()),
						RotationEnabled: types.Bool(false, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "ENCRYPT_DECRYPT KMS Key with auto-rotation enabled",
			input: kms.KMS{
				Metadata: types.NewTestMetadata(),
				Keys: []kms.Key{
					{
						Usage:           types.String("ENCRYPT_DECRYPT", types.NewTestMetadata()),
						RotationEnabled: types.Bool(true, types.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
		{
			name: "SIGN_VERIFY KMS Key with auto-rotation disabled",
			input: kms.KMS{
				Metadata: types.NewTestMetadata(),
				Keys: []kms.Key{
					{
						Usage:           types.String(kms.KeyUsageSignAndVerify, types.NewTestMetadata()),
						RotationEnabled: types.Bool(false, types.NewTestMetadata()),
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
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckAutoRotateKeys.Rule().LongID() {
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
