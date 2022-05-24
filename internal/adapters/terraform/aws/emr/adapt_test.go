package emr

import (
	"testing"

	"github.com/aquasecurity/defsec/pkg/providers/aws/emr"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/test/testutil"
)

func Test_adaptSecurityConfiguration(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  emr.SecurityConfiguration
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_emr_security_configuration" "foo" {
				name = "emrsc_other"
			
				configuration = <<EOF
			  {
				"EncryptionConfiguration": {
				  "AtRestEncryptionConfiguration": {
					"S3EncryptionConfiguration": {
					  "EncryptionMode": "SSE-S3"
					},
					"LocalDiskEncryptionConfiguration": {
					  "EncryptionKeyProviderType": "AwsKms",
					  "AwsKmsKey": "arn:aws:kms:us-west-2:187416307283:alias/tf_emr_test_key"
					}
				  },
				  "EnableInTransitEncryption": false,
				  "EnableAtRestEncryption": true
				}
			  }
			  EOF
			}
			`,
			expected: emr.SecurityConfiguration{
				Metadata: types.NewTestMetadata(),

				Configuration: types.String(
					`{
					"EncryptionConfiguration": {
					"AtRestEncryptionConfiguration": {
						"S3EncryptionConfiguration": {
						"EncryptionMode": "SSE-S3"
						},
						"LocalDiskEncryptionConfiguration": {
						"EncryptionKeyProviderType": "AwsKms",
						"AwsKmsKey": "arn:aws:kms:us-west-2:187416307283:alias/tf_emr_test_key"
						}
					},
					"EnableInTransitEncryption": false,
					"EnableAtRestEncryption": true
					}
  				}`,
					types.NewTestMetadata()),
			},
		},
		// 		{
		// 			name: "defaults",
		// 			terraform: `
		// 			resource "aws_ecs_task_definition" "example" {
		// 				volume {
		// 					name = "service-storage"

		// 					efs_volume_configuration {
		// 					}
		// 				  }
		// 			  }
		// `,
		// 			expected: ecs.TaskDefinition{
		// 				Metadata: types.NewTestMetadata(),
		// 				Volumes: []ecs.Volume{
		// 					{
		// 						Metadata: types.NewTestMetadata(),
		// 						EFSVolumeConfiguration: ecs.EFSVolumeConfiguration{

		// 							Metadata:                 types.NewTestMetadata(),
		// 							TransitEncryptionEnabled: types.Bool(false, types.NewTestMetadata()),
		// 						},
		// 					},
		// 				},
		// 				ContainerDefinitions: types.String("", types.NewTestMetadata()),
		// 			},
		// 		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptSecurityConfiguration(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

// func TestLines(t *testing.T) {
// 	src := `
// 	resource "aws_ecs_cluster" "example" {
// 		name = "services-cluster"

// 		setting {
// 		  name  = "containerInsights"
// 		  value = "enabled"
// 		}
// 	}

// 	resource "aws_ecs_task_definition" "example" {
// 		family                = "service"
// 		container_definitions = <<EOF
// 	[
// 		{
// 			"name": "my_service",
// 			"essential": true,
// 			"memory": 256,
// 			"environment": [
// 				{ "name": "ENVIRONMENT", "value": "development" }
// 			]
// 		}
// 	]
// 		EOF

// 		volume {
// 		  name = "service-storage"

// 		  efs_volume_configuration {
// 			transit_encryption      = "ENABLED"
// 		  }
// 		}
// 	  }`

// 	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
// 	adapted := Adapt(modules)

// 	require.Len(t, adapted.Clusters, 1)
// 	require.Len(t, adapted.TaskDefinitions, 1)

// 	cluster := adapted.Clusters[0]
// 	taskDefinition := adapted.TaskDefinitions[0]

// 	assert.Equal(t, 2, cluster.GetMetadata().Range().GetStartLine())
// 	assert.Equal(t, 9, cluster.GetMetadata().Range().GetEndLine())

// 	assert.Equal(t, 5, cluster.Settings.GetMetadata().Range().GetStartLine())
// 	assert.Equal(t, 8, cluster.Settings.GetMetadata().Range().GetEndLine())

// 	assert.Equal(t, 7, cluster.Settings.ContainerInsightsEnabled.GetMetadata().Range().GetStartLine())
// 	assert.Equal(t, 7, cluster.Settings.ContainerInsightsEnabled.GetMetadata().Range().GetEndLine())

// 	assert.Equal(t, 11, taskDefinition.GetMetadata().Range().GetStartLine())
// 	assert.Equal(t, 33, taskDefinition.GetMetadata().Range().GetEndLine())

// 	assert.Equal(t, 13, taskDefinition.ContainerDefinitions.GetMetadata().Range().GetStartLine())
// 	assert.Equal(t, 24, taskDefinition.ContainerDefinitions.GetMetadata().Range().GetEndLine())

// 	assert.Equal(t, 26, taskDefinition.Volumes[0].GetMetadata().Range().GetStartLine())
// 	assert.Equal(t, 32, taskDefinition.Volumes[0].GetMetadata().Range().GetEndLine())

// 	assert.Equal(t, 29, taskDefinition.Volumes[0].EFSVolumeConfiguration.GetMetadata().Range().GetStartLine())
// 	assert.Equal(t, 31, taskDefinition.Volumes[0].EFSVolumeConfiguration.GetMetadata().Range().GetEndLine())

// 	assert.Equal(t, 30, taskDefinition.Volumes[0].EFSVolumeConfiguration.TransitEncryptionEnabled.GetMetadata().Range().GetStartLine())
// 	assert.Equal(t, 30, taskDefinition.Volumes[0].EFSVolumeConfiguration.TransitEncryptionEnabled.GetMetadata().Range().GetEndLine())
// }
