package keyvault

import (
	"testing"
	"time"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/keyvault"
	"github.com/aquasecurity/defsec/pkg/scan"

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
				Vaults: []keyvault.Vault{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Secrets: []keyvault.Secret{
							{
								Metadata:   defsecTypes.NewTestMetadata(),
								ExpiryDate: defsecTypes.Time(time.Time{}, defsecTypes.NewTestMetadata().GetMetadata()),
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
				Vaults: []keyvault.Vault{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Secrets: []keyvault.Secret{
							{
								Metadata:   defsecTypes.NewTestMetadata(),
								ExpiryDate: defsecTypes.Time(time.Now(), defsecTypes.NewTestMetadata().GetMetadata()),
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
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnsureSecretExpiry.Rule().LongID() {
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
