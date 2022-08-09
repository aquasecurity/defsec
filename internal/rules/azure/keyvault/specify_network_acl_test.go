package keyvault

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/keyvault"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckSpecifyNetworkAcl(t *testing.T) {
	tests := []struct {
		name     string
		input    keyvault.KeyVault
		expected bool
	}{
		{
			name: "Network ACL default action set to allow",
			input: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata: types2.NewTestMetadata(),
						NetworkACLs: keyvault.NetworkACLs{
							Metadata:      types2.NewTestMetadata(),
							DefaultAction: types2.String("Allow", types2.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Network ACL default action set to deny",
			input: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata: types2.NewTestMetadata(),
						NetworkACLs: keyvault.NetworkACLs{
							Metadata:      types2.NewTestMetadata(),
							DefaultAction: types2.String("Deny", types2.NewTestMetadata()),
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
			results := CheckSpecifyNetworkAcl.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckSpecifyNetworkAcl.Rule().LongID() {
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
