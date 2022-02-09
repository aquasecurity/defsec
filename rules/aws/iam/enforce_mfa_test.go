package iam

import (
	"testing"

	"github.com/aquasecurity/defsec/provider/aws/iam"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
	"github.com/aquasecurity/trivy-config-parsers/types"
	"github.com/stretchr/testify/assert"
)

func TestCheckEnforceMFA(t *testing.T) {
	tests := []struct {
		name     string
		input    iam.IAM
		expected bool
	}{
		{
			name: "IAM policy with no MFA required",
			input: iam.IAM{
				Metadata: types.NewTestMetadata(),
				Groups: []iam.Group{
					{
						Metadata: types.NewTestMetadata(),
						Policies: []iam.Policy{
							{
								Metadata: types.NewTestMetadata(),
								Document: types.String(`{
								"Version": "2012-10-17",
								"Statement": [
								  {
									"Sid": "",
									"Effect": "Allow",
									"Action": "ec2:*",
									"Resource": "*"
								  }
								]
							  }`, types.NewTestMetadata()),
							},
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "IAM policy with MFA required",
			input: iam.IAM{
				Metadata: types.NewTestMetadata(),
				Groups: []iam.Group{
					{
						Metadata: types.NewTestMetadata(),
						Policies: []iam.Policy{
							{
								Metadata: types.NewTestMetadata(),
								Document: types.String(`{
								"Version": "2012-10-17",
								"Statement": [
								  {
									"Sid": "",
									"Effect": "Allow",
									"Action": "ec2:*",
									"Resource": "*",
									"Condition": {
										"Bool": {
											"aws:MultiFactorAuthPresent": ["true"]
										}
									}
								  }
								]
							  }`, types.NewTestMetadata()),
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
			testState.AWS.IAM = test.input
			results := CheckEnforceMFA.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() != rules.StatusPassed && result.Rule().LongID() == CheckEnforceMFA.Rule().LongID() {
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
