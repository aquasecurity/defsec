
Don't enable public access to EKS Clusters

```hcl
resource "aws_eks_cluster" "good_example" {
  // other config
  
  name = "good_example_cluster"
  role_arn = var.cluster_arn
  vpc_config {
    endpoint_public_access = true
    public_access_cidrs = ["10.2.0.0/8"]
  }
}
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/eks_cluster#vpc_config
        