package rdb

var terraformSpecifyBackupRetentionGoodExamples = []string{
	` 
   resource "nifcloud_db_instance" "good_example" {
 	allocated_storage       = 100
 	engine                  = "mysql"
 	engine_version          = "5.7"
 	instance_class          = "db.large8"
 	name                    = "mydb"
 	username                = "foo"
 	password                = "foobarbaz"
 	parameter_group_name    = "default.mysql5.7"
 	backup_retention_period = 5
 	skip_final_snapshot     = true
 }
 `,
}

var terraformSpecifyBackupRetentionBadExamples = []string{
	`
 resource "nifcloud_db_instance" "bad_example" {
 	allocated_storage    = 100
 	engine               = "mysql"
 	engine_version       = "5.7"
 	instance_class       = "db.large8"
 	name                 = "mydb"
 	username             = "foo"
 	password             = "foobarbaz"
 	parameter_group_name = "default.mysql5.7"
 	skip_final_snapshot  = true
 }
`,
}

var terraformSpecifyBackupRetentionLinks = []string{
	`https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/db_instance#backup_retention_period`,
}

var terraformSpecifyBackupRetentionRemediationMarkdown = ``
