package lambda

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/aws/lambda"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckRestrictSourceArn(t *testing.T) {
	tests := []struct {
		name     string
		input    lambda.Lambda
		expected bool
	}{
		{
			name: "Lambda function permission missing source ARN",
			input: lambda.Lambda{
				Functions: []lambda.Function{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Permissions: []lambda.Permission{
							{
								Metadata:  defsecTypes.NewTestMetadata(),
								Principal: defsecTypes.String("sns.amazonaws.com", defsecTypes.NewTestMetadata()),
								SourceARN: defsecTypes.String("", defsecTypes.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Lambda function permission with source ARN",
			input: lambda.Lambda{
				Functions: []lambda.Function{
					{
						Metadata: defsecTypes.NewTestMetadata(),
						Permissions: []lambda.Permission{
							{
								Metadata:  defsecTypes.NewTestMetadata(),
								Principal: defsecTypes.String("sns.amazonaws.com", defsecTypes.NewTestMetadata()),
								SourceARN: defsecTypes.String("source-arn", defsecTypes.NewTestMetadata()),
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
			testState.AWS.Lambda = test.input
			results := CheckRestrictSourceArn.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckRestrictSourceArn.Rule().LongID() {
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
