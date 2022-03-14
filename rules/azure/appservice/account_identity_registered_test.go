package appservice

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/azure/appservice"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckAccountIdentityRegistered(t *testing.T) {
	tests := []struct {
		name     string
		input    appservice.AppService
		expected bool
	}{
		{
			name: "App service identity not registered",
			input: appservice.AppService{
				Metadata: types.NewTestMetadata(),
				Services: []appservice.Service{
					{
						Metadata: types.NewTestMetadata(),
						Identity: struct{ Type types.StringValue }{
							Type: types.String("", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "App service identity registered",
			input: appservice.AppService{
				Metadata: types.NewTestMetadata(),
				Services: []appservice.Service{
					{
						Metadata: types.NewTestMetadata(),
						Identity: struct{ Type types.StringValue }{
							Type: types.String("UserAssigned", types.NewTestMetadata()),
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
			results := CheckAccountIdentityRegistered.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == rules.StatusFailed && result.Rule().LongID() == CheckAccountIdentityRegistered.Rule().LongID() {
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
