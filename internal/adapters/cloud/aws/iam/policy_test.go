package iam

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"

	iamapi "github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws/test"
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/elgohr/go-localstack"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type policyDetails struct {
	policyName     string
	policyDocument string
}

func Test_IAMPolicies(t *testing.T) {
	tests := []struct {
		name    string
		details policyDetails
	}{
		{
			name: "basic policy",
			details: policyDetails{
				policyName: "test-policy",
				policyDocument: `{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Action": [
                "iam:GetContextKeysForCustomPolicy",
                "iam:GetContextKeysForPrincipalPolicy",
                "iam:SimulateCustomPolicy",
                "iam:SimulatePrincipalPolicy"
            ],
            "Effect": "Allow",
            "Resource": "*"
        }
    ]
}`,
			},
		},
	}

	rootAdapter, _, err := test.CreateLocalstackAdapter(t, localstack.SQS)
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			arn := bootstrapIAMPolicy(t, rootAdapter, tt.details)
			testState := &state.State{}
			iamAdapter := &adapter{}
			err := iamAdapter.Adapt(rootAdapter, testState)
			require.NoError(t, err)

			var found int
			var match iam.Policy
			for _, policy := range testState.AWS.IAM.Policies {
				if policy.Name.EqualTo(tt.details.policyName) {
					found++
					match = policy
				}
			}
			require.Equal(t, 1, found)
			assert.Equal(t, arn, match.Metadata.Range().GetLocalFilename())
		})
	}
}

func bootstrapIAMPolicy(t *testing.T, ra *aws.RootAdapter, details policyDetails) string {
	api := iamapi.NewFromConfig(ra.SessionConfig())
	output, err := api.CreatePolicy(ra.Context(), &iamapi.CreatePolicyInput{
		PolicyDocument: &details.policyDocument,
		PolicyName:     &details.policyName,
	})
	require.NoError(t, err)
	return *output.Policy.Arn
}
