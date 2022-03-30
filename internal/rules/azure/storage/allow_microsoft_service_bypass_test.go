package storage

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/storage"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckAllowMicrosoftServiceBypass(t *testing.T) {
	tests := []struct {
		name     string
		input    storage.Storage
		expected bool
	}{
		{
			name: "Azure storage rule doesn't allow bypass access",
			input: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: types.NewTestMetadata(),
						NetworkRules: []storage.NetworkRule{
							{
								Metadata: types.NewTestMetadata(),
								Bypass:   []types.StringValue{},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Azure storage rule allows bypass access to Microsoft services",
			input: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata: types.NewTestMetadata(),
						NetworkRules: []storage.NetworkRule{
							{
								Metadata: types.NewTestMetadata(),
								Bypass: []types.StringValue{
									types.String("AzureServices", types.NewTestMetadata()),
								},
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
			testState.Azure.Storage = test.input
			results := CheckAllowMicrosoftServiceBypass.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckAllowMicrosoftServiceBypass.Rule().LongID() {
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
