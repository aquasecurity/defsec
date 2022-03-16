package appservice

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/azure/appservice"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/stretchr/testify/assert"
)

func TestCheckEnableHttp2(t *testing.T) {
	tests := []struct {
		name     string
		input    appservice.AppService
		expected bool
	}{
		{
			name: "HTTP2 disabled",
			input: appservice.AppService{
				Metadata: types.NewTestMetadata(),
				Services: []appservice.Service{
					{
						Metadata: types.NewTestMetadata(),
						Site: struct {
							EnableHTTP2       types.BoolValue
							MinimumTLSVersion types.StringValue
						}{
							EnableHTTP2: types.Bool(false, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "HTTP2 enabled",
			input: appservice.AppService{
				Metadata: types.NewTestMetadata(),
				Services: []appservice.Service{
					{
						Metadata: types.NewTestMetadata(),
						Site: struct {
							EnableHTTP2       types.BoolValue
							MinimumTLSVersion types.StringValue
						}{
							EnableHTTP2: types.Bool(true, types.NewTestMetadata()),
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
			results := CheckEnableHttp2.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == rules.StatusFailed && result.Rule().LongID() == CheckEnableHttp2.Rule().LongID() {
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
