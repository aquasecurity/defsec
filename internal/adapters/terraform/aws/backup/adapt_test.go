package backup

import (
	"testing"

	defsecTypes "github.com/aquasecurity/defsec/pkg/types"

	"github.com/aquasecurity/defsec/pkg/providers/aws/backup"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_adaptVaults(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  backup.Vault
	}{
		{
			name: "backup vault",
			terraform: `
			resource "aws_backup_vault" "example" {
				name        = "example_backup_vault"
				arn         = "aws_backup_vault.example.arn"
				kms_key_arn = "aws_kms_key.example.arn"
			  }
`,
			expected: backup.Vault{
				Metadata: defsecTypes.NewTestMetadata(),
				Name:     defsecTypes.String("example_backup_vault", defsecTypes.NewTestMetadata()),
				Arn:      defsecTypes.String("aws_backup_vault.example.arn", defsecTypes.NewTestMetadata()),
				KeyArn:   defsecTypes.String("aws_kms_key.example.arn", defsecTypes.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
		    resource "aws_appmesh_mesh" "simple" {
		}
`,
			expected: backup.Vault{
				Metadata: defsecTypes.NewTestMetadata(),
				Name:     defsecTypes.String("", defsecTypes.NewTestMetadata()),
				Arn:      defsecTypes.String("", defsecTypes.NewTestMetadata()),
				KeyArn:   defsecTypes.String("", defsecTypes.NewTestMetadata()),
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptVault(modules.GetBlocks()[0], modules[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "aws_backup_vault" "example" {
		name        = "example_backup_vault"
		arn         = "aws_backup_vault.example.arn"
		kms_key_arn = "aws_kms_key.example.arn"
	  }`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Vaults, 1)

	Vault := adapted.Vaults[0]

	assert.Equal(t, 2, Vault.Metadata.Range().GetStartLine())
	assert.Equal(t, 6, Vault.Metadata.Range().GetEndLine())

	assert.Equal(t, 3, Vault.Name.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 3, Vault.Name.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 4, Vault.Arn.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 4, Vault.Arn.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 5, Vault.KeyArn.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, Vault.KeyArn.GetMetadata().Range().GetEndLine())
}
