package rdb

var terraformAddDescriptionToDBSecurityGroupGoodExamples = []string{
	`
 resource "nifcloud_db_security_group" "good_example" {
   group_name  = "app"
   description = "Allow from app traffic"
 }
 `,
}

var terraformAddDescriptionToDBSecurityGroupBadExamples = []string{
	`
 resource "nifcloud_db_security_group" "bad_example" {
   name        = "app"
   description = ""
 }
 `,
}

var terraformAddDescriptionToDBSecurityGroupLinks = []string{
	`https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/db_security_group#description`,
}

var terraformAddDescriptionToDBSecurityGroupRemediationMarkdown = ``
