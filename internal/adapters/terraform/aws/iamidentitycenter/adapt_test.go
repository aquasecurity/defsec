package iamidentitycenter

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/iamidentitycenter"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptPermissionSet(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  iamidentitycenter.PermissionSet
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_ssoadmin_permission_set" "example" {
				session_duration = "PT2H"
			}
`,
			expected: iamidentitycenter.PermissionSet{
				Metadata:        defsecTypes.NewTestMetadata(),
				SessionDuration: defsecTypes.String("PT2H", defsecTypes.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_ssoadmin_permission_set" "example" {
			}
`,
			expected: iamidentitycenter.PermissionSet{
				Metadata:        defsecTypes.NewTestMetadata(),
				SessionDuration: defsecTypes.String("", defsecTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptPermissionSet(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_ssoadmin_permission_set" "example" {
		session_duration = "PT2H"
	}`
	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.PermissionSets, 1)
	permissionSet := adapted.PermissionSets[0]

	assert.Equal(t, 2, permissionSet.Metadata.Range().GetStartLine())
	assert.Equal(t, 4, permissionSet.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, permissionSet.SessionDuration.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, permissionSet.SessionDuration.GetMetadata().Range().GetEndLine())
}
