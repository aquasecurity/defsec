
Remove the public endpoint from the RDS instance'

```hcl
 resource "aws_db_instance" "good_example" {
 	publicly_accessible = false
 }

```


