package rdb

var terraformNoCommonPrivateDBInstanceGoodExamples = []string{
	`
 resource "nifcloud_db_instance" "good_example" {
   network_id = nifcloud_private_lan.main.id
 }
 `,
}

var terraformNoCommonPrivateDBInstanceBadExamples = []string{
	`
 resource "nifcloud_db_instance" "bad_example" {
   network_id = "net-COMMON_PRIVATE"
 }
 `,
}

var terraformNoCommonPrivateDBInstanceLinks = []string{
	`https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/db_instance#network_id`,
}

var terraformNoCommonPrivateDBInstanceRemediationMarkdown = ``
