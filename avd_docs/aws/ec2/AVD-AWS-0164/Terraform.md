
Set the instance to not be publicly accessible

```hcl
 resource "aws_subnet" "good_example" {
	vpc_id                  = "vpc-123456"
	map_public_ip_on_launch = false
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/subnet#map_public_ip_on_launch

