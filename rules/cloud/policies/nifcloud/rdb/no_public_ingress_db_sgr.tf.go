package rdb

var terraformNoPublicIngressDBSgrGoodExamples = []string{
	`
 resource "nifcloud_db_security_group" "good_example" {
   rule {
     cidr_ip = "10.0.0.0/16"
   }
 }
 `,
}

var terraformNoPublicIngressDBSgrBadExamples = []string{
	`
 resource "nifcloud_db_security_group" "bad_example" {
   rule {
     cidr_ip = "0.0.0.0/0"
   }
 }
 `,
}

var terraformNoPublicIngressDBSgrLinks = []string{
	`https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/db_security_group#cidr_ip`,
}

var terraformNoPublicIngressDBSgrRemediationMarkdown = ``
