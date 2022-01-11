
Enable SSL enforcement

```hcl
resource "azurerm_postgresql_server" "good_example" {
  name                = "good_example"
  
  public_network_access_enabled    = false
  ssl_enforcement_enabled          = true
  ssl_minimal_tls_version_enforced = "TLS1_2"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_server#ssl_enforcement_enabled
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server#ssl_enforcement_enabled
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mariadb_server#ssl_enforcement_enabled
        