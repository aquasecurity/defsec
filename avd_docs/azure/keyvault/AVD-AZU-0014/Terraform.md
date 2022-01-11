
Set an expiration date on the vault key

```hcl
resource "azurerm_key_vault_key" "good_example" {
  name         = "generated-certificate"
  key_vault_id = azurerm_key_vault.example.id
  key_type     = "RSA"
  key_size     = 2048
  expiration_date = "1982-12-31T00:00:00Z"
  
  key_opts = [
  "decrypt",
  "encrypt",
  "sign",
  "unwrapKey",
  "verify",
  "wrapKey",
  ]
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/key_vault_key#expiration_date
        