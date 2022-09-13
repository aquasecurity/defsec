
Enable tracing

```hcl
 resource "aws_api_gateway_rest_api" "test" {
	
 }

 resource "aws_api_gateway_stage" "good_example" {
   stage_name    = "prod"
   rest_api_id   = aws_api_gateway_rest_api.test.id
   deployment_id = aws_api_gateway_deployment.test.id
   xray_tracing_enabled = true
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_stage#xray_tracing_enabled

