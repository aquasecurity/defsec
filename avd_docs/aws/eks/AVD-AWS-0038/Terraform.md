---
additional_links: 
  - "https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#enabled_cluster_log_types"
---

Enable logging for the EKS control plane

```hcl
resource "aws_eks_cluster" "good_example" {
     encryption_config {
         resources = [ "secrets" ]
         provider {
             key_arn = var.kms_arn
         }
     }
 
 	enabled_cluster_log_types = ["api", "authenticator", "audit", "scheduler", "controllerManager"]
 
     name = "good_example_cluster"
     role_arn = var.cluster_arn
     vpc_config {
         endpoint_public_access = false
     }
 }
```
