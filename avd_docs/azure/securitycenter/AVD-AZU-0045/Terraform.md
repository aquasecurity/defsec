---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/security_center_subscription_pricing#tier"
---

Enable standard subscription tier to benefit from Azure Defender

```hcl
resource "azurerm_security_center_subscription_pricing" "good_example" {
   tier          = "Standard"
   resource_type = "VirtualMachines"
 }
```
