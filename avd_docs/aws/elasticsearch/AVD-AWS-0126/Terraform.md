
Use the most modern TLS/SSL policies available

```hcl
 resource "aws_elasticsearch_domain" "good_example" {
   domain_name = "domain-foo"
 
   domain_endpoint_options {
     enforce_https = true
     tls_security_policy = "Policy-Min-TLS-1-2-2019-07"
   }
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#tls_security_policy

