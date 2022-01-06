---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#log_type"
---

Enable logging for ElasticSearch domains

```hcl
resource "aws_elasticsearch_domain" "good_example" {
   domain_name           = "example"
   elasticsearch_version = "1.5"
 
   log_publishing_options {
     cloudwatch_log_group_arn = aws_cloudwatch_log_group.example.arn
     log_type                 = "AUDIT_LOGS"
     enabled                  = true  
   }
 }
```
