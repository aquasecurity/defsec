
Explicitly set the retention period to greater than the default

```hcl
 resource "aws_rds_cluster" "good_example" {
 	cluster_identifier      = "aurora-cluster-demo"
 	engine                  = "aurora-mysql"
 	engine_version          = "5.7.mysql_aurora.2.03.2"
 	availability_zones      = ["us-west-2a", "us-west-2b", "us-west-2c"]
 	database_name           = "mydb"
 	master_username         = "foo"
 	master_password         = "bar"
 	backup_retention_period = 5
 	preferred_backup_window = "07:00-09:00"
   }
 

```
```hcl 
   resource "aws_db_instance" "good_example" {
 	allocated_storage    = 10
 	engine               = "mysql"
 	engine_version       = "5.7"
 	instance_class       = "db.t3.micro"
 	name                 = "mydb"
 	username             = "foo"
 	password             = "foobarbaz"
 	parameter_group_name = "default.mysql5.7"
 	backup_retention_period = 5
 	skip_final_snapshot  = true
 }
 
```

#### Remediation Links
 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/rds_cluster#backup_retention_period

 - https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance#backup_retention_period

