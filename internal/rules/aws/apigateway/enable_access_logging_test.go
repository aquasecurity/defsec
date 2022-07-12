package apigateway

import (
	"testing"

	v1 "github.com/aquasecurity/defsec/pkg/providers/aws/apigateway/v1"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableAccessLogging(t *testing.T) {
	tests := []struct {
		name     string
		input    v1.APIGateway
		expected bool
	}{
		{
			name: "API Gateway stage with no log group ARN",
			input: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: types.NewTestMetadata(),
						Stages: []v1.Stage{
							{
								Metadata: types.NewTestMetadata(),
								AccessLogging: v1.AccessLogging{
									Metadata:              types.NewTestMetadata(),
									CloudwatchLogGroupARN: types.String("", types.NewTestMetadata()),
								},
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "API Gateway stage with log group ARN",
			input: v1.APIGateway{
				APIs: []v1.API{
					{
						Metadata: types.NewTestMetadata(),
						Stages: []v1.Stage{
							{
								Metadata: types.NewTestMetadata(),
								AccessLogging: v1.AccessLogging{
									Metadata:              types.NewTestMetadata(),
									CloudwatchLogGroupARN: types.String("log-group-arn", types.NewTestMetadata()),
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
			results := CheckEnableAccessLogging.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckEnableAccessLogging.Rule().LongID() {
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
