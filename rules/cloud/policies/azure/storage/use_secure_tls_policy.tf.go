package storage

var terraformUseSecureTlsPolicyGoodExamples = []string{
	`
 resource "azurerm_storage_account" "good_example" {
   name                     = "storageaccountname"
   resource_group_name      = azurerm_resource_group.example.name
   location                 = azurerm_resource_group.example.location
 }
 `,
}

var terraformUseSecureTlsPolicyBadExamples = []string{
	`
 resource "azurerm_storage_account" "bad_example" {
   name                     = "storageaccountname"
   resource_group_name      = azurerm_resource_group.example.name
   location                 = azurerm_resource_group.example.location
   min_tls_version          = "TLS1_0"
 }
 `,
}

var terraformUseSecureTlsPolicyLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/storage_account#min_tls_version`,
}

var terraformUseSecureTlsPolicyRemediationMarkdown = ``
