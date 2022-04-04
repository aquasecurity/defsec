package ecs

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"

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
				Metadata:                 types.NewTestMetadata(),
				ContainerInsightsEnabled: types.Bool(true, types.NewTestMetadata()),
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
				Metadata:                 types.NewTestMetadata(),
				ContainerInsightsEnabled: types.Bool(false, types.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_ecs_cluster" "example" {			
			}
`,
			expected: ecs.ClusterSettings{
				Metadata:                 types.NewTestMetadata(),
				ContainerInsightsEnabled: types.Bool(false, types.NewTestMetadata()),
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
			  }
`,
			expected: ecs.TaskDefinition{
				Metadata: types.NewTestMetadata(),
				Volumes: []ecs.Volume{
					{
						Metadata: types.NewTestMetadata(),
						EFSVolumeConfiguration: ecs.EFSVolumeConfiguration{
							Metadata:                 types.NewTestMetadata(),
							TransitEncryptionEnabled: types.Bool(true, types.NewTestMetadata()),
						},
					},
				},
				ContainerDefinitions: types.String(
					`[
	{
	"name": "my_service",
	"essential": true,
	"memory": 256,
	"environment": [
		{ "name": "ENVIRONMENT", "value": "development" }
	]
	}
]
`,
					types.NewTestMetadata()),
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
				Metadata: types.NewTestMetadata(),
				Volumes: []ecs.Volume{
					{
						Metadata: types.NewTestMetadata(),
						EFSVolumeConfiguration: ecs.EFSVolumeConfiguration{

							Metadata:                 types.NewTestMetadata(),
							TransitEncryptionEnabled: types.Bool(false, types.NewTestMetadata()),
						},
					},
				},
				ContainerDefinitions: types.String("", types.NewTestMetadata()),
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

	assert.Equal(t, 13, taskDefinition.ContainerDefinitions.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 24, taskDefinition.ContainerDefinitions.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 26, taskDefinition.Volumes[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 32, taskDefinition.Volumes[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 29, taskDefinition.Volumes[0].EFSVolumeConfiguration.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 31, taskDefinition.Volumes[0].EFSVolumeConfiguration.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 30, taskDefinition.Volumes[0].EFSVolumeConfiguration.TransitEncryptionEnabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 30, taskDefinition.Volumes[0].EFSVolumeConfiguration.TransitEncryptionEnabled.GetMetadata().Range().GetEndLine())
}
