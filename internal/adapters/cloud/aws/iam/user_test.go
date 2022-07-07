package iam

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws"

	iamapi "github.com/aws/aws-sdk-go-v2/service/iam"

	"github.com/aquasecurity/defsec/internal/adapters/cloud/aws/test"
	"github.com/aquasecurity/defsec/pkg/providers/aws/iam"
	"github.com/aquasecurity/defsec/pkg/state"
	"github.com/elgohr/go-localstack"
	"github.com/stretchr/testify/require"
)

type userDetails struct {
	name string
}

func Test_IAMUsers(t *testing.T) {
	tests := []struct {
		name    string
		details userDetails
	}{
		{
			name: "basic user",
			details: userDetails{
				name: "test-user",
			},
		},
	}

	rootAdapter, _, err := test.CreateLocalstackAdapter(t, localstack.SQS)
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			arn := bootstrapIAMUser(t, rootAdapter, tt.details)
			testState := &state.State{}
			iamAdapter := &adapter{}
			err := iamAdapter.Adapt(rootAdapter, testState)
			require.NoError(t, err)

			var found int
			var match iam.User
			for _, user := range testState.AWS.IAM.Users {
				if user.Name.EqualTo(tt.details.name) {
					found++
					match = user
				}
			}
			require.Equal(t, 1, found)
			assert.Equal(t, arn, match.Metadata.Range().GetLocalFilename())
		})
	}
}

func bootstrapIAMUser(t *testing.T, ra *aws.RootAdapter, details userDetails) string {
	api := iamapi.NewFromConfig(ra.SessionConfig())
	output, err := api.CreateUser(ra.Context(), &iamapi.CreateUserInput{
		UserName: &details.name,
	})
	require.NoError(t, err)
	return *output.User.Arn
}
