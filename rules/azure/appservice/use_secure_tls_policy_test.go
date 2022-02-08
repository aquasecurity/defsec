package appservice

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/azure/appservice"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/defsec/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckUseSecureTlsPolicy(t *testing.T) {
	tests := []struct {
		name     string
		input    appservice.AppService
		expected bool
	}{
		{
			name: "Minimum TLS version TLS1_0",
			input: appservice.AppService{
				Metadata: types.NewTestMetadata(),
				Services: []appservice.Service{
					{
						Metadata: types.NewTestMetadata(),
						Site: struct {
							EnableHTTP2       types.BoolValue
							MinimumTLSVersion types.StringValue
						}{
							EnableHTTP2:       types.Bool(true, types.NewTestMetadata()),
							MinimumTLSVersion: types.String("1.0", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Minimum TLS version TLS1_2",
			input: appservice.AppService{
				Metadata: types.NewTestMetadata(),
				Services: []appservice.Service{
					{
						Metadata: types.NewTestMetadata(),
						Site: struct {
							EnableHTTP2       types.BoolValue
							MinimumTLSVersion types.StringValue
						}{
							EnableHTTP2:       types.Bool(true, types.NewTestMetadata()),
							MinimumTLSVersion: types.String("1.2", types.NewTestMetadata()),
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
			results := CheckUseSecureTlsPolicy.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckUseSecureTlsPolicy.Rule().LongID() {
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
