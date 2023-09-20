
Disable skip final snapshot at RDS clusters

```hcl
 resource "aws_rds_cluster" "good_example" {
 	skip_final_snapshot = false
 }

```
