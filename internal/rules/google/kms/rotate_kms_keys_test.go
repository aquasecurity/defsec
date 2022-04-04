package kms

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/google/kms"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckRotateKmsKeys(t *testing.T) {
	tests := []struct {
		name     string
		input    kms.KMS
		expected bool
	}{
		{
			name: "KMS key rotation period of 91 days",
			input: kms.KMS{
				KeyRings: []kms.KeyRing{
					{
						Metadata: types.NewTestMetadata(),
						Keys: []kms.Key{
							{
								Metadata:              types.NewTestMetadata(),
								RotationPeriodSeconds: types.Int(7862400, types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "KMS key rotation period of 30 days",
			input: kms.KMS{
				KeyRings: []kms.KeyRing{
					{
						Metadata: types.NewTestMetadata(),
						Keys: []kms.Key{
							{
								Metadata:              types.NewTestMetadata(),
								RotationPeriodSeconds: types.Int(2592000, types.NewTestMetadata()),
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
			testState.Google.KMS = test.input
			results := CheckRotateKmsKeys.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRotateKmsKeys.Rule().LongID() {
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
