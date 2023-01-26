package autoscaling

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/autoscaling"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptCluster(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  autoscaling.AutoscalingGroupsList
	}{
		{
			name: "configured",
			terraform: `		
			resource "aws_autoscaling_group" "example" {
			 name     = "my-group"
			 availability_zones = "us-east-1a"
			 
			  
			}

`,
			expected: autoscaling.AutoscalingGroupsList{
				Metadata: defsecTypes.NewTestMetadata(),
				Name:     defsecTypes.String("my-group", defsecTypes.NewTestMetadata()),
				AvaiabilityZone: []defsecTypes.StringValue{
					defsecTypes.String("us-east-1a", defsecTypes.NewTestMetadata()),
				},
			},
		},
		{
			name: "defaults",
			terraform: `		
			resource "aws_autoscaling_group" "example"  {
			}
`,
			expected: autoscaling.AutoscalingGroupsList{
				Metadata: defsecTypes.NewTestMetadata(),
				Name:     defsecTypes.String("", defsecTypes.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptAutoscaling(modules.GetBlocks()[0], modules[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_autoscaling_group" "example" {
		name     = "my-group"
		availability_zones = "us-east-1a"
		
		 
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.AutoscalingGroupsList, 1)

	autoscalingGroupsList := adapted.AutoscalingGroupsList[0]

	assert.Equal(t, 2, autoscalingGroupsList.Metadata.Range().GetStartLine())
	assert.Equal(t, 7, autoscalingGroupsList.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, autoscalingGroupsList.Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, autoscalingGroupsList.Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, autoscalingGroupsList.AvaiabilityZone[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, autoscalingGroupsList.AvaiabilityZone[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, autoscalingGroupsList.HealthCheckType.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, autoscalingGroupsList.HealthCheckType.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, autoscalingGroupsList.LoadBalancerNames[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, autoscalingGroupsList.LoadBalancerNames[0].GetMetadata().Range().GetEndLine())

}
