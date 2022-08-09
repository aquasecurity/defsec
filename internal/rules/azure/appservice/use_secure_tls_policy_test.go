package appservice

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

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
						Metadata: types2.NewTestMetadata(),
						Site: struct {
							EnableHTTP2       types2.BoolValue
							MinimumTLSVersion types2.StringValue
						}{
							EnableHTTP2:       types2.Bool(true, types2.NewTestMetadata()),
							MinimumTLSVersion: types2.String("1.0", types2.NewTestMetadata()),
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
						Metadata: types2.NewTestMetadata(),
						Site: struct {
							EnableHTTP2       types2.BoolValue
							MinimumTLSVersion types2.StringValue
						}{
							EnableHTTP2:       types2.Bool(true, types2.NewTestMetadata()),
							MinimumTLSVersion: types2.String("1.2", types2.NewTestMetadata()),
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
