---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_method#authorization"
---

Use and authorization method or require API Key

```hcl
resource "aws_api_gateway_rest_api" "MyDemoAPI" {
	
 }

 resource "aws_api_gateway_method" "good_example" {
   rest_api_id   = aws_api_gateway_rest_api.MyDemoAPI.id
   resource_id   = aws_api_gateway_resource.MyDemoResource.id
   http_method   = "GET"
   authorization = "AWS_IAM"
 }
```
