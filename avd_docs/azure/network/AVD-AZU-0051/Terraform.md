
Set a more restrictive cidr range

```hcl
resource "azurerm_network_security_rule" "good_example" {
  direction = "Outbound"
  destination_address_prefix = "10.0.0.0/16"
  access = "Allow"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/network_security_rule
        