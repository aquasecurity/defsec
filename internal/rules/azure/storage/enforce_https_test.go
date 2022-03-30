package storage

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/storage"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnforceHttps(t *testing.T) {
	tests := []struct {
		name     string
		input    storage.Storage
		expected bool
	}{
		{
			name: "Storage account HTTPS enforcement disabled",
			input: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata:     types.NewTestMetadata(),
						EnforceHTTPS: types.Bool(false, types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Storage account HTTPS enforcement enabled",
			input: storage.Storage{
				Accounts: []storage.Account{
					{
						Metadata:     types.NewTestMetadata(),
						EnforceHTTPS: types.Bool(true, types.NewTestMetadata()),
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
			results := CheckEnforceHttps.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnforceHttps.Rule().LongID() {
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
