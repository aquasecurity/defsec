package actions

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/github"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/trivy-config-parsers/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckNoPlainTextActionEnvironmentSecrets(t *testing.T) {
	tests := []struct {
		name     string
		input    []github.EnvironmentSecret
		expected bool
	}{
		{
			name: "Github actions environment secret has plain text value",
			input: []github.EnvironmentSecret{
				{
					Metadata:       types.NewTestMetadata(),
					PlainTextValue: types.String("sensitive secret string", types.NewTestMetadata()),
				},
			},
			expected: true,
		},
		{
			name: "Github actions environment secret has no plain text value",
			input: []github.EnvironmentSecret{
				{
					Metadata:       types.NewTestMetadata(),
					PlainTextValue: types.String("", types.NewTestMetadata()),
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.GitHub.EnvironmentSecrets = test.input
			results := CheckNoPlainTextActionEnvironmentSecrets.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckNoPlainTextActionEnvironmentSecrets.Rule().LongID() {
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
