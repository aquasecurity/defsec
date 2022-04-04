package keyvault

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/keyvault"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPurge(t *testing.T) {
	tests := []struct {
		name     string
		input    keyvault.KeyVault
		expected bool
	}{
		{
			name: "Keyvault purge protection disabled",
			input: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata:                types.NewTestMetadata(),
						EnablePurgeProtection:   types.Bool(false, types.NewTestMetadata()),
						SoftDeleteRetentionDays: types.Int(30, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Keyvault purge protection enabled but soft delete retention period set to 3 days",
			input: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata:                types.NewTestMetadata(),
						EnablePurgeProtection:   types.Bool(true, types.NewTestMetadata()),
						SoftDeleteRetentionDays: types.Int(3, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Keyvault purge protection enabled and soft delete retention period set to 30 days",
			input: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata:                types.NewTestMetadata(),
						EnablePurgeProtection:   types.Bool(true, types.NewTestMetadata()),
						SoftDeleteRetentionDays: types.Int(30, types.NewTestMetadata()),
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
			results := CheckNoPurge.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPurge.Rule().LongID() {
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
