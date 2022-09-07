
Enable encryption on managed disks

```hcl
 resource "azurerm_managed_disk" "good_example" {
 	encryption_settings {
 		enabled = true
 	}
 }
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/managed_disk

