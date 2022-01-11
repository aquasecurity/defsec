
Use the most modern TLS policies available

```hcl
resource "azurerm_mssql_server" "good_example" {
  name                         = "mssqlserver"
  resource_group_name          = azurerm_resource_group.example.name
  location                     = azurerm_resource_group.example.location
  version                      = "12.0"
  administrator_login          = "missadministrator"
  administrator_login_password = "thisIsKat11"
  minimum_tls_version          = "1.2"
}

resource "azurerm_postgresql_server" "good_example" {
  name                = "bad_example"
  
  public_network_access_enabled    = true
  ssl_enforcement_enabled          = false
  ssl_minimal_tls_version_enforced = "TLS1_2"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mssql_server#minimum_tls_version
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/mysql_server#ssl_minimal_tls_version_enforced
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/postgresql_server#ssl_minimal_tls_version_enforced
        