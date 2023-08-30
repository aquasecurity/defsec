
Enable capture for all locations

```hcl
 resource "azurerm_monitor_log_profile" "good_example" {
   name = "bad_example"
 
   categories = []
 
   locations = [
 	"eastus",
 	"eastus2",
 	"southcentralus",
 	"westus2",
 	"westus3",
 	"australiaeast",
 	"southeastasia",
 	"northeurope",
 	"swedencentral",
 	"uksouth",
 	"westeurope",
 	"centralus",
 	"northcentralus",
 	"westus",
 	"southafricanorth",
 	"centralindia",
 	"eastasia",
 	"japaneast",
 	"jioindiawest",
 	"koreacentral",
 	"canadacentral",
 	"francecentral",
 	"germanywestcentral",
 	"norwayeast",
 	"switzerlandnorth",
 	"uaenorth",
 	"brazilsouth",
 	"centralusstage",
 	"eastusstage",
 	"eastus2stage",
 	"northcentralusstage",
 	"southcentralusstage",
 	"westusstage",
 	"westus2stage",
 	"asia",
 	"asiapacific",
 	"australia",
 	"brazil",
 	"canada",
 	"europe",
 	"global",
 	"india",
 	"japan",
 	"uk",
 	"unitedstates",
 	"eastasiastage",
 	"southeastasiastage",
 	"centraluseuap",
 	"eastus2euap",
 	"westcentralus",
 	"southafricawest",
 	"australiacentral",
 	"australiacentral2",
 	"australiasoutheast",
 	"japanwest",
 	"jioindiacentral",
 	"koreasouth",
 	"southindia",
 	"westindia",
 	"canadaeast",
 	"francesouth",
 	"germanynorth",
 	"norwaywest",
 	"swedensouth",
 	"switzerlandwest",
 	"ukwest",
 	"uaecentral",
 	"brazilsoutheast",
   ]
 
   retention_policy {
     enabled = true
     days    = 7
   }
 }
 
 			
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/azurerm/latest/docs/resources/monitor_log_profile#locations

