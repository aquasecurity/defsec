package appservice

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/appservice"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnforceHttps(t *testing.T) {
	tests := []struct {
		name     string
		input    appservice.AppService
		expected bool
	}{
		{
			name: "Function app doesn't enforce HTTPS",
			input: appservice.AppService{
				FunctionApps: []appservice.FunctionApp{
					{
						Metadata:  types2.NewTestMetadata(),
						HTTPSOnly: types2.Bool(false, types2.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "Function app enforces HTTPS",
			input: appservice.AppService{
				FunctionApps: []appservice.FunctionApp{
					{
						Metadata:  types2.NewTestMetadata(),
						HTTPSOnly: types2.Bool(true, types2.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.Azure.AppService = test.input
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
