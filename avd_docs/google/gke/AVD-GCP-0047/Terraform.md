---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/google/latest/docs/resources/container_cluster#pod_security_policy_config"
---

Use security policies for pods to restrict permissions to those needed to be effective

```hcl
resource "google_container_cluster" "good_example" {
 	pod_security_policy_config {
         enabled = "true"
 	}
 }
```
