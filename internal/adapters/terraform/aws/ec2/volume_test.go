package ec2

import (
	"testing"

	types2 "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/ec2"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptVolume(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  ec2.Volume
	}{
		{
			name: "referenced key",
			terraform: `
			resource "aws_ebs_volume" "example" {
				kms_key_id = aws_kms_key.ebs_encryption.arn
				encrypted = true
			}

			resource "aws_kms_key" "ebs_encryption" {
				enable_key_rotation = true
			}
`,
			expected: ec2.Volume{
				Metadata: types2.NewTestMetadata(),
				Encryption: ec2.Encryption{
					Metadata: types2.NewTestMetadata(),
					Enabled:  types2.Bool(true, types2.NewTestMetadata()),
					KMSKeyID: types2.String("aws_kms_key.ebs_encryption", types2.NewTestMetadata()),
				},
			},
		},
		{
			name: "string key",
			terraform: `
			resource "aws_ebs_volume" "example" {
				kms_key_id = "string-key"
				encrypted = true
			}
`,
			expected: ec2.Volume{
				Metadata: types2.NewTestMetadata(),
				Encryption: ec2.Encryption{
					Metadata: types2.NewTestMetadata(),
					Enabled:  types2.Bool(true, types2.NewTestMetadata()),
					KMSKeyID: types2.String("string-key", types2.NewTestMetadata()),
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_ebs_volume" "example" {
			}
`,
			expected: ec2.Volume{
				Metadata: types2.NewTestMetadata(),
				Encryption: ec2.Encryption{
					Metadata: types2.NewTestMetadata(),
					Enabled:  types2.Bool(false, types2.NewTestMetadata()),
					KMSKeyID: types2.String("", types2.NewTestMetadata()),
				},
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptVolume(modules.GetBlocks()[0], modules[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestVolumeLines(t *testing.T) {
	src := `
	resource "aws_ebs_volume" "example" {
		kms_key_id = aws_kms_key.ebs_encryption.arn
		encrypted = true
	}

	resource "aws_kms_key" "ebs_encryption" {
		enable_key_rotation = true
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Volumes, 1)
	volume := adapted.Volumes[0]

	assert.Equal(t, 2, volume.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, volume.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, volume.Encryption.Enabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, volume.Encryption.Enabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 7, volume.Encryption.KMSKeyID.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 9, volume.Encryption.KMSKeyID.GetMetadata().Range().GetEndLine())
}
