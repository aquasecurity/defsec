package ec2

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptRouteTable(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  ec2.RouteTable
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_route_table" "example" {
				id = "rtb-4fbb3ac4"
			}
`,
			expected: ec2.RouteTable{
				Metadata:     defsecTypes.NewTestMetadata(),
				RouteTableId: defsecTypes.String("rtb-4fbb3ac4", defsecTypes.NewTestMetadata()),
			},
		},

		{
			name: "defaults",
			terraform: `
			resource "aws_route_table" "example" {
			    id = ""
			}
`,
			expected: ec2.RouteTable{
				Metadata:     defsecTypes.NewTestMetadata(),
				RouteTableId: defsecTypes.String("", defsecTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptRouteTable(modules.GetBlocks()[0], modules[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}

}

func TestRouteTableLines(t *testing.T) {
	src := `
	resource "aws_route_table" "example"{
	   id = "rtb-4fbb3ac4"
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.RouteTables, 1)
	routetable := adapted.RouteTables[0]

	assert.Equal(t, 2, routetable.Metadata.Range().GetStartLine())
	assert.Equal(t, 4, routetable.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, routetable.RouteTableId.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, routetable.RouteTableId.GetMetadata().Range().GetEndLine())
}
