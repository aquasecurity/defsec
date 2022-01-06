---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/elasticsearch_domain#encrypt_at_rest"
---

Enable encrypted node to node communication

```hcl
resource "aws_elasticsearch_domain" "good_example" {
   domain_name = "domain-foo"
 
   node_to_node_encryption {
     enabled = true
   }
 }
```
