package nas

var terraformNoCommonPrivateNASInstanceGoodExamples = []string{
	`
 resource "nifcloud_nas_instance" "good_example" {
   network_id = nifcloud_private_lan.main.id
 }
 `,
}

var terraformNoCommonPrivateNASInstanceBadExamples = []string{
	`
 resource "nifcloud_nas_instance" "bad_example" {
   network_id = "net-COMMON_PRIVATE"
 }
 `,
}

var terraformNoCommonPrivateNASInstanceLinks = []string{
	`https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/nas_instance#network_id`,
}

var terraformNoCommonPrivateNASInstanceRemediationMarkdown = ``
