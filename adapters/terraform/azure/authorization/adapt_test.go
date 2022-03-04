package authorization

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/testutil"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/providers/azure/authorization"
)

func Test_adaptRoleDefinition(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  authorization.RoleDefinition
	}{
		{
			name: "wildcard actions and data reference scope",
			terraform: `
			resource "azurerm_role_definition" "example" {
				name        = "my-custom-role"
	  
				permissions {
				  actions     = ["*"]
				  not_actions = []
				}

				assignable_scopes = [
				  data.azurerm_subscription.primary.id,
				]
			}
`,
			expected: authorization.RoleDefinition{
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
					types.String("Data Reference", types.NewTestMetadata()),
				},
			},
		},
		{
			name: "no actions and wildcard scope",
			terraform: `
			resource "azurerm_role_definition" "example" {
				name        = "my-custom-role"
	  
				permissions {
				  actions     = []
				  not_actions = []
				}

				assignable_scopes = [
					"/"
				]
			}
`,
			expected: authorization.RoleDefinition{
				Metadata: types.NewTestMetadata(),
				Permissions: []authorization.Permission{
					{
						Metadata: types.NewTestMetadata(),
					},
				},
				AssignableScopes: []types.StringValue{
					types.String("/", types.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptRoleDefinition(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "azurerm_role_definition" "example" {
		name        = "my-custom-role"

		permissions {
		  actions     = ["*"]
		  not_actions = []
		}

		assignable_scopes = ["/"]
	}`

	modules := testutil.CreateModulesFromSource(src, ".tf", t)
	adapted := Adapt(modules)

	require.Len(t, adapted.RoleDefinitions, 1)
	require.Len(t, adapted.RoleDefinitions[0].Permissions, 1)
	require.Len(t, adapted.RoleDefinitions[0].AssignableScopes, 1)

	assert.Equal(t, 6, adapted.RoleDefinitions[0].Permissions[0].Actions[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, adapted.RoleDefinitions[0].Permissions[0].Actions[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, adapted.RoleDefinitions[0].AssignableScopes[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, adapted.RoleDefinitions[0].AssignableScopes[0].GetMetadata().Range().GetEndLine())

}
