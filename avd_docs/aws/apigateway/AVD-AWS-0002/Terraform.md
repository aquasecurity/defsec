
Enable cache encryption

```hcl
resource "aws_api_gateway_rest_api" "example" {
  
}

resource "aws_api_gateway_stage" "example" {
  
}

resource "aws_api_gateway_method_settings" "good_example" {
  rest_api_id = aws_api_gateway_rest_api.example.id
  stage_name  = aws_api_gateway_stage.example.stage_name
  method_path = "path1/GET"
  
  settings {
    metrics_enabled = true
    logging_level   = "INFO"
    cache_data_encrypted = true
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_method_settings#cache_data_encrypted
        