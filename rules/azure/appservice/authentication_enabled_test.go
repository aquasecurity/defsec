package appservice

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/azure/appservice"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/defsec/types"
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
				Metadata: types.NewTestMetadata(),
				Services: []appservice.Service{
					{
						Metadata: types.NewTestMetadata(),
						Authentication: struct{ Enabled types.BoolValue }{
							Enabled: types.Bool(false, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "App service authentication enabled",
			input: appservice.AppService{
				Metadata: types.NewTestMetadata(),
				Services: []appservice.Service{
					{
						Metadata: types.NewTestMetadata(),
						Authentication: struct{ Enabled types.BoolValue }{
							Enabled: types.Bool(true, types.NewTestMetadata()),
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
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckAuthenticationEnabled.Rule().LongID() {
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
