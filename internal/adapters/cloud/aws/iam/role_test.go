package iam

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"

	iamapi "github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws/test"
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/stretchr/testify/require"
)

type roleDetails struct {
	name     string
	document string
}

func Test_IAMRoles(t *testing.T) {
	tests := []struct {
		name    string
		details roleDetails
	}{
		{
			name: "basic role",
			details: roleDetails{
				name: "test-group",
				document: `{
    "Version": "2012-10-17",
    "Statement": {
        "Effect": "Allow",
        "Principal": { "AWS": "arn:aws:iam::123456789012:root" },
        "Action": "sts:AssumeRole"
    }
}`,
			},
		},
	}
	ra, stack, err := test.CreateLocalstackAdapter(t)
	defer func() { _ = stack.Stop() }()
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			arn := bootstrapIAMRole(t, ra, tt.details)
			testState := &state.State{}
			iamAdapter := &adapter{}
			err := iamAdapter.Adapt(ra, testState)
			require.NoError(t, err)

			var found int
			var match iam.Role
			for _, role := range testState.AWS.IAM.Roles {
				if role.Name.EqualTo(tt.details.name) {
					found++
					match = role
				}
			}
			require.Equal(t, 1, found)
			assert.Equal(t, arn, match.Metadata.Range().GetLocalFilename())
		})
	}
}

func bootstrapIAMRole(t *testing.T, ra *aws.RootAdapter, details roleDetails) string {
	api := iamapi.NewFromConfig(ra.SessionConfig())
	output, err := api.CreateRole(ra.Context(), &iamapi.CreateRoleInput{
		RoleName:                 &details.name,
		AssumeRolePolicyDocument: &details.document,
	})
	require.NoError(t, err)
	return *output.Role.Arn
}
