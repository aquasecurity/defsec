package appservice

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/appservice"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckAuthenticationEnabled(t *testing.T) {
	tests := []struct {
		name     string
		input    appservice.AppService
		expected bool
	}{
		{
			name: "App service authentication disabled",
			input: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: types2.NewTestMetadata(),
						Authentication: struct{ Enabled types2.BoolValue }{
							Enabled: types2.Bool(false, types2.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "App service authentication enabled",
			input: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: types2.NewTestMetadata(),
						Authentication: struct{ Enabled types2.BoolValue }{
							Enabled: types2.Bool(true, types2.NewTestMetadata()),
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
			testState.Azure.AppService = test.input
			results := CheckAuthenticationEnabled.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckAuthenticationEnabled.Rule().LongID() {
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
