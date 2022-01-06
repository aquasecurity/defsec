---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#enforce_https"
---

Enforce the use of HTTPS for ElasticSearch

```hcl
resource "aws_elasticsearch_domain" "good_example" {
   domain_name = "domain-foo"
 
   domain_endpoint_options {
     enforce_https = true
   }
 }
```
