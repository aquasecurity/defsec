package synapse

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/testutil"
	"github.com/aquasecurity/defsec/parsers/types"

	"github.com/aquasecurity/defsec/providers/azure/synapse"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptWorkspace(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  synapse.Workspace
	}{
		{
			name: "enabled",
			terraform: `
			resource "azurerm_synapse_workspace" "example" {
				managed_virtual_network_enabled	   = true
			}
`,
			expected: synapse.Workspace{
				Metadata:                    types.NewTestMetadata(),
				EnableManagedVirtualNetwork: types.Bool(true, types.NewTestMetadata()),
			},
		},
		{
			name: "disabled",
			terraform: `
			resource "azurerm_synapse_workspace" "example" {
				managed_virtual_network_enabled	   = false
			}
`,
			expected: synapse.Workspace{
				Metadata:                    types.NewTestMetadata(),
				EnableManagedVirtualNetwork: types.Bool(false, types.NewTestMetadata()),
			},
		},
		{
			name: "default",
			terraform: `
			resource "azurerm_synapse_workspace" "example" {
			}
`,
			expected: synapse.Workspace{
				Metadata:                    types.NewTestMetadata(),
				EnableManagedVirtualNetwork: types.Bool(false, types.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptWorkspace(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "azurerm_synapse_workspace" "example" {
		managed_virtual_network_enabled	   = true
	  }`

	modules := testutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Workspaces, 1)
	workspace := adapted.Workspaces[0]

	assert.Equal(t, 3, workspace.EnableManagedVirtualNetwork.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, workspace.EnableManagedVirtualNetwork.GetMetadata().Range().GetEndLine())
}
