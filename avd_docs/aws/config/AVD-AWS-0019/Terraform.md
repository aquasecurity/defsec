---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/config_configuration_aggregator#all_regions"
---

Set the aggregator to cover all regions

```hcl
resource "aws_config_configuration_aggregator" "good_example" {
 	name = "example"
 	  
 	account_aggregation_source {
 	  account_ids = ["123456789012"]
 	  all_regions = true
 	}
 }
```
