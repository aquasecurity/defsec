package keyvault

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/keyvault"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckContentTypeForSecret(t *testing.T) {
	tests := []struct {
		name     string
		input    keyvault.KeyVault
		expected bool
	}{
		{
			name: "Key vault secret content-type not specified",
			input: keyvault.KeyVault{
				Metadata: types.NewTestMetadata(),
				Vaults: []keyvault.Vault{
					{
						Metadata: types.NewTestMetadata(),
						Secrets: []keyvault.Secret{
							{
								Metadata:    types.NewTestMetadata(),
								ContentType: types.String("", types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Key vault secret content-type specified",
			input: keyvault.KeyVault{
				Metadata: types.NewTestMetadata(),
				Vaults: []keyvault.Vault{
					{
						Metadata: types.NewTestMetadata(),
						Secrets: []keyvault.Secret{
							{
								Metadata:    types.NewTestMetadata(),
								ContentType: types.String("password", types.NewTestMetadata()),
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
			results := CheckContentTypeForSecret.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckContentTypeForSecret.Rule().LongID() {
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
