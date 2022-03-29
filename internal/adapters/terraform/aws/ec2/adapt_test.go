package ec2

import (
	"testing"

	"github.com/aquasecurity/defsec/internal/types"
	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  ec2.EC2
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_instance" "example" {
				ami = "ami-7f89a64f"
				instance_type = "t1.micro"
			  
				root_block_device {
					encrypted = true
				}

				metadata_options {
					http_tokens = "required"
					http_endpoint = "disabled"
				}	
			  
				ebs_block_device {
				  encrypted = true
				}

				user_data = <<EOF
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
				EOF
			}
`,
			expected: ec2.EC2{
				Metadata: types.NewTestMetadata(),
				Instances: []ec2.Instance{
					{
						Metadata: types.NewTestMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							Metadata:     types.NewTestMetadata(),
							HttpTokens:   types.String("required", types.NewTestMetadata()),
							HttpEndpoint: types.String("disabled", types.NewTestMetadata()),
						},
						UserData: types.String(
							`export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
`,
							types.NewTestMetadata()),
						RootBlockDevice: &ec2.BlockDevice{
							Metadata:  types.NewTestMetadata(),
							Encrypted: types.Bool(true, types.NewTestMetadata()),
						},
						EBSBlockDevices: []ec2.BlockDevice{
							{
								Metadata:  types.NewTestMetadata(),
								Encrypted: types.Bool(true, types.NewTestMetadata()),
							},
						},
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_instance" "example" {
			}
`,
			expected: ec2.EC2{
				Metadata: types.NewTestMetadata(),
				Instances: []ec2.Instance{
					{
						Metadata: types.NewTestMetadata(),
						MetadataOptions: ec2.MetadataOptions{
							Metadata:     types.NewTestMetadata(),
							HttpTokens:   types.String("", types.NewTestMetadata()),
							HttpEndpoint: types.String("", types.NewTestMetadata()),
						},
						UserData: types.String("", types.NewTestMetadata()),
						RootBlockDevice: &ec2.BlockDevice{
							Metadata:  types.NewTestMetadata(),
							Encrypted: types.Bool(false, types.NewTestMetadata()),
						},
					},
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := Adapt(modules)
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_instance" "example" {
		ami = "ami-7f89a64f"
		instance_type = "t1.micro"
	  
		root_block_device {
			encrypted = true
		}

		metadata_options {
			http_tokens = "required"
			http_endpoint = "disabled"
		}	
	  
		ebs_block_device {
		  encrypted = true
		}

		user_data = <<EOF
export AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
		EOF
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Instances, 1)
	instance := adapted.Instances[0]

	assert.Equal(t, 2, instance.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 22, instance.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 6, instance.RootBlockDevice.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 8, instance.RootBlockDevice.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 7, instance.RootBlockDevice.Encrypted.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 7, instance.RootBlockDevice.Encrypted.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, instance.MetadataOptions.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 13, instance.MetadataOptions.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 11, instance.MetadataOptions.HttpTokens.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 11, instance.MetadataOptions.HttpTokens.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 12, instance.MetadataOptions.HttpEndpoint.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 12, instance.MetadataOptions.HttpEndpoint.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 15, instance.EBSBlockDevices[0].GetMetadata().Range().GetStartLine())
	assert.Equal(t, 17, instance.EBSBlockDevices[0].GetMetadata().Range().GetEndLine())

	assert.Equal(t, 16, instance.EBSBlockDevices[0].Encrypted.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 16, instance.EBSBlockDevices[0].Encrypted.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 19, instance.UserData.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 21, instance.UserData.GetMetadata().Range().GetEndLine())
}
