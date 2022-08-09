package ecs

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ecs"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptClusterSettings(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  ecs.ClusterSettings
	}{
		{
			name: "container insights enabled",
			terraform: `
			resource "aws_ecs_cluster" "example" {
				name = "services-cluster"
			  
				setting {
				  name  = "containerInsights"
				  value = "enabled"
				}
			}
`,
			expected: ecs.ClusterSettings{
				Metadata:                 types2.NewTestMetadata(),
				ContainerInsightsEnabled: types2.Bool(true, types2.NewTestMetadata()),
			},
		},
		{
			name: "invalid name",
			terraform: `
			resource "aws_ecs_cluster" "example" {
				name = "services-cluster"
			  
				setting {
				  name  = "invalidName"
				  value = "enabled"
				}
			}
`,
			expected: ecs.ClusterSettings{
				Metadata:                 types2.NewTestMetadata(),
				ContainerInsightsEnabled: types2.Bool(false, types2.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_ecs_cluster" "example" {			
			}
`,
			expected: ecs.ClusterSettings{
				Metadata:                 types2.NewTestMetadata(),
				ContainerInsightsEnabled: types2.Bool(false, types2.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptClusterSettings(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptTaskDefinitionResource(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  ecs.TaskDefinition
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_ecs_task_definition" "example" {
				family                = "service"
				container_definitions = <<EOF
[
	{
	"name": "my_service",
	"image": "my_image",
	"essential": true,
	"memory": 256,
	"cpu": 2,
	"environment": [
		{ "name": "ENVIRONMENT", "value": "development" }
	]
	}
]
				EOF
			  
				volume {
				  name = "service-storage"
			  
				  efs_volume_configuration {
					transit_encryption      = "ENABLED"
				  }
				}
			  }
`,
			expected: ecs.TaskDefinition{
				Metadata: types2.NewTestMetadata(),
				Volumes: []ecs.Volume{
					{
						Metadata: types2.NewTestMetadata(),
						EFSVolumeConfiguration: ecs.EFSVolumeConfiguration{
							Metadata:                 types2.NewTestMetadata(),
							TransitEncryptionEnabled: types2.Bool(true, types2.NewTestMetadata()),
						},
					},
				},
				ContainerDefinitions: []ecs.ContainerDefinition{
					{
						Metadata:   types2.NewTestMetadata(),
						Name:       types2.String("my_service", types2.NewTestMetadata()),
						Image:      types2.String("my_image", types2.NewTestMetadata()),
						CPU:        types2.Int(2, types2.NewTestMetadata()),
						Memory:     types2.Int(256, types2.NewTestMetadata()),
						Essential:  types2.Bool(true, types2.NewTestMetadata()),
						Privileged: types2.Bool(false, types2.NewTestMetadata()),
						Environment: []ecs.EnvVar{
							{
								Name:  "ENVIRONMENT",
								Value: "development",
							},
						},
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_ecs_task_definition" "example" {
				volume {
					name = "service-storage"
				
					efs_volume_configuration {
					}
				  }
			  }
`,
			expected: ecs.TaskDefinition{
				Metadata: types2.NewTestMetadata(),
				Volumes: []ecs.Volume{
					{
						Metadata: types2.NewTestMetadata(),
						EFSVolumeConfiguration: ecs.EFSVolumeConfiguration{

							Metadata:                 types2.NewTestMetadata(),
							TransitEncryptionEnabled: types2.Bool(false, types2.NewTestMetadata()),
						},
					},
				},
				ContainerDefinitions: nil,
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptTaskDefinitionResource(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_ecs_cluster" "example" {
		name = "services-cluster"
	  
		setting {
		  name  = "containerInsights"
		  value = "enabled"
		}
	}

	resource "aws_ecs_task_definition" "example" {
		family                = "service"
		container_definitions = <<EOF
	[
		{
			"name": "my_service",
			"essential": true,
			"memory": 256,
			"environment": [
				{ "name": "ENVIRONMENT", "value": "development" }
			]
		}
	]
		EOF
	  
		volume {
		  name = "service-storage"
	  
		  efs_volume_configuration {
			transit_encryption      = "ENABLED"
		  }
		}
	  }`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Clusters, 1)
	require.Len(t, adapted.TaskDefinitions, 1)

	cluster := adapted.Clusters[0]
	taskDefinition := adapted.TaskDefinitions[0]

	assert.Equal(t, 2, cluster.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 9, cluster.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, cluster.Settings.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 8, cluster.Settings.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 7, cluster.Settings.ContainerInsightsEnabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, cluster.Settings.ContainerInsightsEnabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, taskDefinition.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 33, taskDefinition.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 26, taskDefinition.Volumes[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 32, taskDefinition.Volumes[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 29, taskDefinition.Volumes[0].EFSVolumeConfiguration.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 31, taskDefinition.Volumes[0].EFSVolumeConfiguration.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 30, taskDefinition.Volumes[0].EFSVolumeConfiguration.TransitEncryptionEnabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 30, taskDefinition.Volumes[0].EFSVolumeConfiguration.TransitEncryptionEnabled.GetMetadata().Range().GetEndLine())
}
