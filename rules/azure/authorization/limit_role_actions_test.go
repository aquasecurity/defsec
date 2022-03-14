package authorization

import (
	"testing"

	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/azure/authorization"
	"github.com/aquasecurity/defsec/rules"
	"github.com/aquasecurity/defsec/state"
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
				Metadata: types.NewTestMetadata(),
				RoleDefinitions: []authorization.RoleDefinition{
					{
						Metadata: types.NewTestMetadata(),
						Permissions: []authorization.Permission{
							{
								Metadata: types.NewTestMetadata(),
								Actions: []types.StringValue{
									types.String("*", types.NewTestMetadata()),
								},
							},
						},
						AssignableScopes: []types.StringValue{
							types.String("/", types.NewTestMetadata()),
						},
					},
				},
			},
			expected: true,
		},
		{
			name: "Wildcard action with specific scope",
			input: authorization.Authorization{
				Metadata: types.NewTestMetadata(),
				RoleDefinitions: []authorization.RoleDefinition{
					{
						Metadata: types.NewTestMetadata(),
						Permissions: []authorization.Permission{
							{
								Metadata: types.NewTestMetadata(),
								Actions: []types.StringValue{
									types.String("*", types.NewTestMetadata()),
								},
							},
						},
						AssignableScopes: []types.StringValue{
							types.String("proper-scope", types.NewTestMetadata()),
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
				if result.Status() == rules.StatusFailed && result.Rule().LongID() == CheckLimitRoleActions.Rule().LongID() {
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
