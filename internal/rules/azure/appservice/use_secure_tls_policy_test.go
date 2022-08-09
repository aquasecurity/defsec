package appservice

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/appservice"
	"github.com/aquasecurity/defsec/pkg/scan"

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
				Services: []appservice.Service{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Site: struct {
							EnableHTTP2       defsecTypes.BoolValue
							MinimumTLSVersion defsecTypes.StringValue
						}{
							EnableHTTP2:       defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							MinimumTLSVersion: defsecTypes.String("1.0", defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Minimum TLS version TLS1_2",
			input: appservice.AppService{
				Services: []appservice.Service{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Site: struct {
							EnableHTTP2       defsecTypes.BoolValue
							MinimumTLSVersion defsecTypes.StringValue
						}{
							EnableHTTP2:       defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
							MinimumTLSVersion: defsecTypes.String("1.2", defsecTypes.NewTestMetadata()),
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
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckUseSecureTlsPolicy.Rule().LongID() {
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
