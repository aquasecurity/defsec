package apigateway

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/apigateway"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckUseSecureTlsPolicy(t *testing.T) {
	tests := []struct {
		name     string
		input    apigateway.APIGateway
		expected bool
	}{
		{
			name: "API Gateway domain name with TLS version 1.0",
			input: apigateway.APIGateway{
				DomainNames: []apigateway.DomainName{
					{
						Metadata:       types.NewTestMetadata(),
						SecurityPolicy: types.String("TLS_1_0", types.NewTestMetadata()),
					},
				},
			},
			expected: true,
		},
		{
			name: "API Gateway domain name with TLS version 1.2",
			input: apigateway.APIGateway{
				DomainNames: []apigateway.DomainName{
					{
						Metadata:       types.NewTestMetadata(),
						SecurityPolicy: types.String("TLS_1_2", types.NewTestMetadata()),
					},
				},
			},
			expected: false,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var testState state.State
			testState.AWS.APIGateway = test.input
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
