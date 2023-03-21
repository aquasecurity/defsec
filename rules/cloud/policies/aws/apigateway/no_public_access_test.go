package apigateway

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	v1 "github.com/aquasecurity/defsec/pkg/providers/aws/apigateway/v1"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckNoPublicAccess(t *testing.T) {
	tests := []struct {
		name     string
		input    v1.APIGateway
		expected bool
	}{
		{
			name: "API GET method without authorization",
			input: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Resources: []v1.Resource{
							{
								Methods: []v1.Method{
									{
										Metadata:          defsecTypes.NewTestMetadata(),
										HTTPMethod:        defsecTypes.String("GET", defsecTypes.NewTestMetadata()),
										APIKeyRequired:    defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
										AuthorizationType: defsecTypes.String(v1.AuthorizationNone, defsecTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "API OPTION method without authorization",
			input: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Resources: []v1.Resource{
							{
								Methods: []v1.Method{
									{
										Metadata:          defsecTypes.NewTestMetadata(),
										HTTPMethod:        defsecTypes.String("OPTION", defsecTypes.NewTestMetadata()),
										APIKeyRequired:    defsecTypes.Bool(true, defsecTypes.NewTestMetadata()),
										AuthorizationType: defsecTypes.String(v1.AuthorizationNone, defsecTypes.NewTestMetadata()),
									},
								},
							},
						},
					},
				},
			},
			expected: false,
		},
		{
			name: "API GET method with IAM authorization",
			input: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Resources: []v1.Resource{
							{
								Methods: []v1.Method{
									{
										Metadata:          defsecTypes.NewTestMetadata(),
										HTTPMethod:        defsecTypes.String("GET", defsecTypes.NewTestMetadata()),
										APIKeyRequired:    defsecTypes.Bool(false, defsecTypes.NewTestMetadata()),
										AuthorizationType: defsecTypes.String(v1.AuthorizationIAM, defsecTypes.NewTestMetadata()),
									},
								},
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
			testState.AWS.APIGateway.V1 = test.input
			results := CheckNoPublicAccess.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckNoPublicAccess.Rule().LongID() {
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
