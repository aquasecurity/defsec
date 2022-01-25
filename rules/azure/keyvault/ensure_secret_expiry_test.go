package keyvault

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/azure/keyvault"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckEnsureSecretExpiry(t *testing.T) {
	t.SkipNow()
	tests := []struct {
		name     string
		input    keyvault.KeyVault
		expected bool
	}{
		{
			name:     "positive result",
			input:    keyvault.KeyVault{},
			expected: true,
		},
		{
			name:     "negative result",
			input:    keyvault.KeyVault{},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Azure.KeyVault = test.input
			results := CheckEnsureSecretExpiry.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Rule().LongID() == CheckEnsureSecretExpiry.Rule().LongID() {
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
