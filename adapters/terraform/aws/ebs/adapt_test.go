package ebs

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/tftestutil"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/aquasecurity/defsec/providers/aws/ebs"
)

func Test_adaptVolume(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  ebs.Volume
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
			expected: ebs.Volume{
				Metadata: types.NewTestMetadata(),
				Encryption: ebs.Encryption{
					Metadata: types.NewTestMetadata(),
					Enabled:  types.Bool(true, types.NewTestMetadata()),
					KMSKeyID: types.String("aws_kms_key.ebs_encryption", types.NewTestMetadata()),
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
			expected: ebs.Volume{
				Metadata: types.NewTestMetadata(),
				Encryption: ebs.Encryption{
					Metadata: types.NewTestMetadata(),
					Enabled:  types.Bool(true, types.NewTestMetadata()),
					KMSKeyID: types.String("string-key", types.NewTestMetadata()),
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_ebs_volume" "example" {
			}
`,
			expected: ebs.Volume{
				Metadata: types.NewTestMetadata(),
				Encryption: ebs.Encryption{
					Metadata: types.NewTestMetadata(),
					Enabled:  types.Bool(false, types.NewTestMetadata()),
					KMSKeyID: types.String("", types.NewTestMetadata()),
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

func TestLines(t *testing.T) {
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
