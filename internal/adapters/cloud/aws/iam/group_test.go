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

type groupDetails struct {
	name string
}

func Test_IAMGroups(t *testing.T) {
	tests := []struct {
		name    string
		details groupDetails
	}{
		{
			name: "basic group",
			details: groupDetails{
				name: "test-group",
			},
		},
	}

	ra, stack, err := test.CreateLocalstackAdapter(t)
	defer func() { _ = stack.Stop() }()
	require.NoError(t, err)

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			arn := bootstrapIAMGroup(t, ra, tt.details)
			testState := &state.State{}
			iamAdapter := &adapter{}
			err := iamAdapter.Adapt(ra, testState)
			require.NoError(t, err)

			var found int
			var match iam.Group
			for _, group := range testState.AWS.IAM.Groups {
				if group.Name.EqualTo(tt.details.name) {
					found++
					match = group
				}
			}
			require.Equal(t, 1, found)
			assert.Equal(t, arn, match.Metadata.Range().GetLocalFilename())
		})
	}
}

func bootstrapIAMGroup(t *testing.T, ra *aws.RootAdapter, details groupDetails) string {
	api := iamapi.NewFromConfig(ra.SessionConfig())
	output, err := api.CreateGroup(ra.Context(), &iamapi.CreateGroupInput{
		GroupName: &details.name,
	})
	require.NoError(t, err)
	return *output.Group.Arn
}
