package ssm

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ssm"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckSecretUseCustomerKey(t *testing.T) {
	tests := []struct {
		name     string
		input    ssm.SSM
		expected bool
	}{
		{
			name: "AWS SSM missing KMS key",
			input: ssm.SSM{
				Metadata: types.NewTestMetadata(),
				Secrets: []ssm.Secret{
					{
						Metadata: types.NewTestMetadata(),
						KMSKeyID: types.String("", types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS SSM with default KMS key",
			input: ssm.SSM{
				Metadata: types.NewTestMetadata(),
				Secrets: []ssm.Secret{
					{
						Metadata: types.NewTestMetadata(),
						KMSKeyID: types.String(ssm.DefaultKMSKeyID, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "AWS SSM with proper KMS key",
			input: ssm.SSM{
				Metadata: types.NewTestMetadata(),
				Secrets: []ssm.Secret{
					{
						Metadata: types.NewTestMetadata(),
						KMSKeyID: types.String("some-ok-key", types.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.SSM = test.input
			results := CheckSecretUseCustomerKey.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckSecretUseCustomerKey.Rule().LongID() {
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
