package appmesh

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/pkg/providers/aws/appmesh"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
)

func Test_adaptMesh(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  appmesh.Mesh
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_appmesh_mesh" "simple" {
				spec {
					egress_filter {
					  type = "ALLOW_ALL"
					}
				}
			}	
		   
`,
			expected: appmesh.Mesh{
				Metadata: defsecTypes.NewTestMetadata(),
				Spec: appmesh.Spec{
					Metadata: defsecTypes.NewTestMetadata(),
					EgressFilter: appmesh.EgressFilter{
						Metadata: defsecTypes.NewTestMetadata(),
						Type:     defsecTypes.String("DROP_ALL", defsecTypes.NewTestMetadata()),
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
		    resource "aws_appmesh_mesh" "simple" {
		}
`,
			expected: appmesh.Mesh{
				Metadata: defsecTypes.NewTestMetadata(),
				Spec: appmesh.Spec{
					Metadata: defsecTypes.NewTestMetadata(),
					EgressFilter: appmesh.EgressFilter{
						Metadata: defsecTypes.NewTestMetadata(),
						Type:     defsecTypes.String("DROP_ALL", defsecTypes.NewTestMetadata()),
					},
				},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptMesh(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}

}

func Test_Lines(t *testing.T) {
	src := `
	resource "aws_appmesh_mesh" "simple" {
		spec {
			egress_filter {
				 type = "ALLOW_ALL"
			}
		}
	}`
	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Meshes, 1)
	mesh := adapted.Meshes[0]

	assert.Equal(t, 2, mesh.Metadata.Range().GetStartLine())
	assert.Equal(t, 8, mesh.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, mesh.Spec.Metadata.Range().GetStartLine())
	assert.Equal(t, 7, mesh.Spec.Metadata.Range().GetEndLine())

	assert.Equal(t, 2, mesh.Spec.EgressFilter.Metadata.Range().GetStartLine())
	assert.Equal(t, 8, mesh.Spec.EgressFilter.Metadata.Range().GetEndLine())

	assert.Equal(t, 2, mesh.Spec.EgressFilter.Type.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 8, mesh.Spec.EgressFilter.Type.GetMetadata().Range().GetEndLine())
}
