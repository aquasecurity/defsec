package workspaces

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/testutil"
	"github.com/aquasecurity/defsec/parsers/types"

	"github.com/aquasecurity/defsec/providers/aws/workspaces"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptWorkspace(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  workspaces.WorkSpace
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_workspaces_workspace" "example" {
				root_volume_encryption_enabled = true
				user_volume_encryption_enabled = true
		}
`,
			expected: workspaces.WorkSpace{
				Metadata: types.NewTestMetadata(),
				RootVolume: workspaces.Volume{
					Metadata: types.NewTestMetadata(),
					Encryption: workspaces.Encryption{
						Metadata: types.NewTestMetadata(),
						Enabled:  types.Bool(true, types.NewTestMetadata()),
					},
				},
				UserVolume: workspaces.Volume{
					Metadata: types.NewTestMetadata(),
					Encryption: workspaces.Encryption{
						Metadata: types.NewTestMetadata(),
						Enabled:  types.Bool(true, types.NewTestMetadata()),
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_workspaces_workspace" "example" {
		}
`,
			expected: workspaces.WorkSpace{
				Metadata: types.NewTestMetadata(),
				RootVolume: workspaces.Volume{
					Metadata: types.NewTestMetadata(),
					Encryption: workspaces.Encryption{
						Metadata: types.NewTestMetadata(),
						Enabled:  types.Bool(false, types.NewTestMetadata()),
					},
				},
				UserVolume: workspaces.Volume{
					Metadata: types.NewTestMetadata(),
					Encryption: workspaces.Encryption{
						Metadata: types.NewTestMetadata(),
						Enabled:  types.Bool(false, types.NewTestMetadata()),
					},
				},
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
	resource "aws_workspaces_workspace" "example" {
		root_volume_encryption_enabled = true
		user_volume_encryption_enabled = true
	}`

	modules := testutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.WorkSpaces, 1)
	workspace := adapted.WorkSpaces[0]

	assert.Equal(t, 2, workspace.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, workspace.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 3, workspace.RootVolume.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, workspace.RootVolume.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 3, workspace.RootVolume.Encryption.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, workspace.RootVolume.Encryption.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, workspace.UserVolume.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, workspace.UserVolume.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, workspace.UserVolume.Encryption.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, workspace.UserVolume.Encryption.GetMetadata().Range().GetEndLine())
}
