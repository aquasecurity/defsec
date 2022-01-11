
Use the most modern TLS/SSL policies available

```hcl
resource "aws_api_gateway_domain_name" "good_example" {
  security_policy = "TLS_1_2"
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/api_gateway_domain_name#security_policy
        