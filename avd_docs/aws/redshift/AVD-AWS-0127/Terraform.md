
Deploy Redshift cluster into a non default VPC

```hcl
 resource "aws_redshift_cluster" "good_example" {
 	cluster_identifier = "tf-redshift-cluster"
 	database_name      = "mydb"
 	master_username    = "foo"
 	master_password    = "Mustbe8characters"
 	node_type          = "dc1.large"
 	cluster_type       = "single-node"
 
 	cluster_subnet_group_name = "redshift_subnet"
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/redshift_cluster#cluster_subnet_group_name

