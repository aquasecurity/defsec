package rdb

var terraformNoPublicDbAccessGoodExamples = []string{
	`
 resource "nifcloud_db_instance" "good_example" {
 	publicly_accessible = false
 }
 `,
}

var terraformNoPublicDbAccessBadExamples = []string{
	`
 resource "nifcloud_db_instance" "bad_example" {
 	publicly_accessible = true
 }
 `,
}

var terraformNoPublicDbAccessLinks = []string{
	`https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/db_instance#publicly_accessible`,
}

var terraformNoPublicDbAccessRemediationMarkdown = ``
