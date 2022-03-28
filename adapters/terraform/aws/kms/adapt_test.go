package kms

import (
	"testing"

	"github.com/aquasecurity/defsec/adapters/terraform/testutil"
	"github.com/aquasecurity/defsec/parsers/types"
	"github.com/aquasecurity/defsec/providers/aws/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptKey(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  kms.Key
	}{
		{
			name: "configured",
			terraform: `
			resource "aws_kms_key" "example" {
				enable_key_rotation = true
				key_usage = SIGN_VERIFY
			}
`,
			expected: kms.Key{
				Usage:           types.String(kms.KeyUsageSignAndVerify, types.NewTestMetadata()),
				RotationEnabled: types.Bool(true, types.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "aws_kms_key" "example" {
			}
`,
			expected: kms.Key{
				Usage:           types.String("ENCRYPT_DECRYPT", types.NewTestMetadata()),
				RotationEnabled: types.Bool(false, types.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := testutil.CreateModulesFromSource(test.terraform, ".tf", t)
			adapted := adaptKey(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_kms_key" "example" {
		enable_key_rotation = true
		key_usage = SIGN_VERIFY
	}`

	modules := testutil.CreateModulesFromSource(src, ".tf", t)
	adapted := Adapt(modules)

	require.Len(t, adapted.Keys, 1)
	key := adapted.Keys[0]

	assert.Equal(t, 2, key.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, key.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 3, key.RotationEnabled.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, key.RotationEnabled.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, key.Usage.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, key.Usage.GetMetadata().Range().GetEndLine())

}
