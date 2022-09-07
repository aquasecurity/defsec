
Don't use sensitive credentials in the VM custom_data

```hcl
 resource "azurerm_virtual_machine" "good_example" {
 	name = "good_example"
	os_profile_linux_config {
		disable_password_authentication = false
	}
	os_profile {
		custom_data =<<EOF
			export GREETING="Hello there"
			EOF
	}
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/virtual_machine#custom_data

