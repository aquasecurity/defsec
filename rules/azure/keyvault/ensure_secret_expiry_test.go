package keyvault

import (
	"testing"
	"time"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/provider/azure/keyvault"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckEnsureSecretExpiry(t *testing.T) {
	tests := []struct {
		name     string
		input    keyvault.KeyVault
		expected bool
	}{
		{
			name: "Key vault secret expiration date not set",
			input: keyvault.KeyVault{
				Metadata: types.NewTestMetadata(),
				Vaults: []keyvault.Vault{
					{
						Metadata: types.NewTestMetadata(),
						Secrets: []keyvault.Secret{
							{
								Metadata:   types.NewTestMetadata(),
								ExpiryDate: types.Time(time.Time{}, types.NewTestMetadata().GetMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Key vault secret expiration date specified",
			input: keyvault.KeyVault{
				Metadata: types.NewTestMetadata(),
				Vaults: []keyvault.Vault{
					{
						Metadata: types.NewTestMetadata(),
						Secrets: []keyvault.Secret{
							{
								Metadata:   types.NewTestMetadata(),
								ExpiryDate: types.Time(time.Now(), types.NewTestMetadata().GetMetadata()),
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
			testState.Azure.KeyVault = test.input
			results := CheckEnsureSecretExpiry.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckEnsureSecretExpiry.Rule().LongID() {
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
