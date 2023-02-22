package lambda

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/lambda"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckEnableTracing(t *testing.T) {
	tests := []struct {
		name     string
		input    lambda.Lambda
		expected bool
	}{
		{
			name: "Lambda function with no tracing mode specified",
			input: lambda.Lambda{
				Functions: []lambda.Function{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Tracing: lambda.Tracing{
							Metadata: defsecTypes.NewTestMetadata(),
							Mode:     defsecTypes.String("", defsecTypes.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Lambda function with active tracing mode",
			input: lambda.Lambda{
				Functions: []lambda.Function{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Tracing: lambda.Tracing{
							Metadata: defsecTypes.NewTestMetadata(),
							Mode:     defsecTypes.String(lambda.TracingModeActive, defsecTypes.NewTestMetadata()),
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
			testState.AWS.Lambda = test.input
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
