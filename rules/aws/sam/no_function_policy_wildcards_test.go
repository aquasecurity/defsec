package sam

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/sam"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/defsec/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckNoFunctionPolicyWildcards(t *testing.T) {
	tests := []struct {
		name     string
		input    sam.SAM
		expected bool
	}{
		{
			name: "Wildcard action in function policy",
			input: sam.SAM{
				Metadata: types.NewTestMetadata(),
				Functions: []sam.Function{
					{
						Metadata: types.NewTestMetadata(),
						Policies: []types.StringValue{
							types.String(`{
								"Version": "2012-10-17",
								"Statement": [
								  {
									"Effect": "Allow",
									"Action": ["s3:*"],
									"Resource": ["arn:aws:s3:::my-bucket/*"],
									"Principal": {
										"AWS": "*"
									}
								  }
								]
							  }`, types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Specific action in function policy",
			input: sam.SAM{
				Metadata: types.NewTestMetadata(),
				Functions: []sam.Function{
					{
						Metadata: types.NewTestMetadata(),
						Policies: []types.StringValue{
							types.String(`{
								"Version": "2012-10-17",
								"Statement": [
								  {
									"Effect": "Allow",
									"Action": ["s3:GetObject"],
									"Resource": ["arn:aws:s3:::my-bucket/*"],
									"Principal": {
										"AWS": "proper-value"
									}
								  }
								]
							  }`, types.NewTestMetadata()),
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
			testState.AWS.SAM = test.input
			results := CheckNoFunctionPolicyWildcards.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckNoFunctionPolicyWildcards.Rule().LongID() {
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
