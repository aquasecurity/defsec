package apigateway

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/internal/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/apigateway"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableTracing(t *testing.T) {
	tests := []struct {
		name     string
		input    apigateway.APIGateway
		expected bool
	}{
		{
			name: "API Gateway stage with X-Ray tracing disabled",
			input: apigateway.APIGateway{
				Metadata: types.NewTestMetadata(),
				APIs: []apigateway.API{
					{
						Metadata:     types.NewTestMetadata(),
						ProtocolType: types.String(apigateway.ProtocolTypeREST, types.NewTestMetadata()),
						Stages: []apigateway.Stage{
							{
								Metadata:           types.NewTestMetadata(),
								Version:            types.Int(1, types.NewTestMetadata()),
								XRayTracingEnabled: types.Bool(false, types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "API Gateway stage with X-Ray tracing enabled",
			input: apigateway.APIGateway{
				Metadata: types.NewTestMetadata(),
				APIs: []apigateway.API{
					{
						Metadata:     types.NewTestMetadata(),
						ProtocolType: types.String(apigateway.ProtocolTypeREST, types.NewTestMetadata()),
						Stages: []apigateway.Stage{
							{
								Metadata:           types.NewTestMetadata(),
								Version:            types.Int(1, types.NewTestMetadata()),
								XRayTracingEnabled: types.Bool(true, types.NewTestMetadata()),
							},
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
			testState.AWS.APIGateway = test.input
			results := CheckEnableTracing.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableTracing.Rule().LongID() {
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
