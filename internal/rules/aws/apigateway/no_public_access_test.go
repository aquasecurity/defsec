package apigateway

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

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
						Metadata: types2.NewTestMetadata(),
						Resources: []v1.Resource{
							{
								Methods: []v1.Method{
									{
										Metadata:          types2.NewTestMetadata(),
										HTTPMethod:        types2.String("GET", types2.NewTestMetadata()),
										APIKeyRequired:    types2.Bool(false, types2.NewTestMetadata()),
										AuthorizationType: types2.String(v1.AuthorizationNone, types2.NewTestMetadata()),
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
						Metadata: types2.NewTestMetadata(),
						Resources: []v1.Resource{
							{
								Methods: []v1.Method{
									{
										Metadata:          types2.NewTestMetadata(),
										HTTPMethod:        types2.String("OPTION", types2.NewTestMetadata()),
										APIKeyRequired:    types2.Bool(true, types2.NewTestMetadata()),
										AuthorizationType: types2.String(v1.AuthorizationNone, types2.NewTestMetadata()),
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
						Metadata: types2.NewTestMetadata(),
						Resources: []v1.Resource{
							{
								Methods: []v1.Method{
									{
										Metadata:          types2.NewTestMetadata(),
										HTTPMethod:        types2.String("GET", types2.NewTestMetadata()),
										APIKeyRequired:    types2.Bool(false, types2.NewTestMetadata()),
										AuthorizationType: types2.String(v1.AuthorizationIAM, types2.NewTestMetadata()),
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
