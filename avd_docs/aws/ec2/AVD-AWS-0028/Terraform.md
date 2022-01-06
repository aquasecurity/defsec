---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#metadata-options"
---

Enable HTTP token requirement for IMDS

```hcl
resource "aws_instance" "good_example" {
	 ami           = "ami-005e54dee72cc1d00"
	 instance_type = "t2.micro"
	 metadata_options {
	 http_tokens = "required"
	 }	
 }
```
