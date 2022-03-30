package keyvault

import (
	"testing"
	"time"

	"github.com/aquasecurity/defsec/internal/types"

	"github.com/aquasecurity/defsec/pkg/providers/azure/keyvault"

	"github.com/aquasecurity/defsec/internal/adapters/terraform/tftestutil"

	"github.com/aquasecurity/defsec/test/testutil"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func Test_Adapt(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  keyvault.KeyVault
	}{
		{
			name: "defined",
			terraform: `
			resource "azurerm_key_vault" "example" {
				name                        = "examplekeyvault"
				enabled_for_disk_encryption = true
				soft_delete_retention_days  = 7
				purge_protection_enabled    = true
			
				network_acls {
					bypass = "AzureServices"
					default_action = "Deny"
				}
			}
`,
			expected: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata:                types.NewTestMetadata(),
						EnablePurgeProtection:   types.Bool(true, types.NewTestMetadata()),
						SoftDeleteRetentionDays: types.Int(7, types.NewTestMetadata()),
						NetworkACLs: keyvault.NetworkACLs{
							Metadata:      types.NewTestMetadata(),
							DefaultAction: types.String("Deny", types.NewTestMetadata()),
						},
					},
				},
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "azurerm_key_vault" "example" {
			}
`,
			expected: keyvault.KeyVault{
				Vaults: []keyvault.Vault{
					{
						Metadata:                types.NewTestMetadata(),
						EnablePurgeProtection:   types.Bool(false, types.NewTestMetadata()),
						SoftDeleteRetentionDays: types.Int(0, types.NewTestMetadata()),
						NetworkACLs: keyvault.NetworkACLs{
							Metadata:      types.NewTestMetadata(),
							DefaultAction: types.String("", types.NewTestMetadata()),
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

func Test_adaptSecret(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  keyvault.Secret
	}{
		{
			name: "defaults",
			terraform: `
			resource "azurerm_key_vault_secret" "example" {
			}
`,
			expected: keyvault.Secret{
				Metadata:    types.NewTestMetadata(),
				ContentType: types.String("", types.NewTestMetadata()),
				ExpiryDate:  types.Time(time.Time{}, types.NewTestMetadata()),
			},
		},
		{
			name: "defined",
			terraform: `
			resource "azurerm_key_vault_secret" "example" {
				content_type = "password"
				expiration_date = "1982-12-31T00:00:00Z"
			}
`,
			expected: keyvault.Secret{
				Metadata:    types.NewTestMetadata(),
				ContentType: types.String("password", types.NewTestMetadata()),
				ExpiryDate: types.Time(func(timeVal string) time.Time {
					parsed, _ := time.Parse(time.RFC3339, timeVal)
					return parsed
				}("1982-12-31T00:00:00Z"), types.NewTestMetadata())},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptSecret(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func Test_adaptKey(t *testing.T) {
	tests := []struct {
		name      string
		terraform string
		expected  keyvault.Key
	}{
		{
			name: "defined",
			terraform: `
			resource "azurerm_key_vault_key" "example" {
				name         = "generated-certificate"
				expiration_date = "1982-12-31T00:00:00Z"
			}
`,
			expected: keyvault.Key{
				Metadata: types.NewTestMetadata(),
				ExpiryDate: types.Time(func(timeVal string) time.Time {
					parsed, _ := time.Parse(time.RFC3339, timeVal)
					return parsed
				}("1982-12-31T00:00:00Z"), types.NewTestMetadata()),
			},
		},
		{
			name: "defaults",
			terraform: `
			resource "azurerm_key_vault_key" "example" {
			}
`,
			expected: keyvault.Key{
				Metadata:   types.NewTestMetadata(),
				ExpiryDate: types.Time(time.Time{}, types.NewTestMetadata()),
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			modules := tftestutil.CreateModulesFromSource(t, test.terraform, ".tf")
			adapted := adaptKey(modules.GetBlocks()[0])
			testutil.AssertDefsecEqual(t, test.expected, adapted)
		})
	}
}

func TestLines(t *testing.T) {
	src := `
	resource "azurerm_key_vault" "example" {
		name                        = "examplekeyvault"
		enabled_for_disk_encryption = true
		soft_delete_retention_days  = 7
		purge_protection_enabled    = true
	
		network_acls {
			bypass = "AzureServices"
			default_action = "Deny"
		}
	}

	resource "azurerm_key_vault_key" "example" {
		key_vault_id = azurerm_key_vault.example.id
		name         = "generated-certificate"
		expiration_date = "1982-12-31T00:00:00Z"
	  }

	resource "azurerm_key_vault_secret" "example" {
		key_vault_id = azurerm_key_vault.example.id
		content_type = "password"
		expiration_date = "1982-12-31T00:00:00Z"
	}`

	modules := tftestutil.CreateModulesFromSource(t, src, ".tf")
	adapted := Adapt(modules)

	require.Len(t, adapted.Vaults, 1)
	require.Len(t, adapted.Vaults[0].Keys, 1)
	require.Len(t, adapted.Vaults[0].Secrets, 1)

	vault := adapted.Vaults[0]
	key := vault.Keys[0]
	secret := vault.Secrets[0]

	assert.Equal(t, 5, vault.SoftDeleteRetentionDays.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 5, vault.SoftDeleteRetentionDays.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 6, vault.EnablePurgeProtection.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 6, vault.EnablePurgeProtection.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 10, vault.NetworkACLs.DefaultAction.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 10, vault.NetworkACLs.DefaultAction.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 17, key.ExpiryDate.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 17, key.ExpiryDate.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 22, secret.ContentType.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 22, secret.ContentType.GetMetadata().Range().GetEndLine())

	assert.Equal(t, 23, secret.ExpiryDate.GetMetadata().Range().GetStartLine())
	assert.Equal(t, 23, secret.ExpiryDate.GetMetadata().Range().GetEndLine())
}
