package authorization

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/state"

	"github.com/aquasecurity/defsec/pkg/providers/azure/authorization"
	"github.com/aquasecurity/defsec/pkg/scan"

	"github.com/stretchr/testify/assert"
)

func TestCheckLimitRoleActions(t *testing.T) {
	tests := []struct {
		name     string
		input    authorization.Authorization
		expected bool
	}{
		{
			name: "Wildcard action with all scopes",
			input: authorization.Authorization{
				RoleDefinitions: []authorization.RoleDefinition{
					{
						Metadata: types2.NewTestMetadata(),
						Permissions: []authorization.Permission{
							{
								Metadata: types2.NewTestMetadata(),
								Actions: []types2.StringValue{
									types2.String("*", types2.NewTestMetadata()),
								},
							},
						},
						AssignableScopes: []types2.StringValue{
							types2.String("/", types2.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Wildcard action with specific scope",
			input: authorization.Authorization{
				RoleDefinitions: []authorization.RoleDefinition{
					{
						Metadata: types2.NewTestMetadata(),
						Permissions: []authorization.Permission{
							{
								Metadata: types2.NewTestMetadata(),
								Actions: []types2.StringValue{
									types2.String("*", types2.NewTestMetadata()),
								},
							},
						},
						AssignableScopes: []types2.StringValue{
							types2.String("proper-scope", types2.NewTestMetadata()),
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
			testState.Azure.Authorization = test.input
			results := CheckLimitRoleActions.Evaluate(&testState)
			var found bool
			for _, result := range results {
				if result.Status() == scan.StatusFailed && result.Rule().LongID() == CheckLimitRoleActions.Rule().LongID() {
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
