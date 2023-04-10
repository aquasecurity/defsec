package network

var terraformNoCommonPrivateRouterGoodExamples = []string{
	`
 resource "nifcloud_router" "good_example" {
   security_group  = nifcloud_security_group.example.group_name

   network_interface {
     network_id = nifcloud_private_lan.main.id
   }
 }
 `,
}

var terraformNoCommonPrivateRouterBadExamples = []string{
	`
 resource "nifcloud_router" "bad_example" {
   security_group  = nifcloud_security_group.example.group_name

   network_interface {
     network_id = "net-COMMON_PRIVATE"
   }
 }
 `,
}

var terraformNoCommonPrivateRouterLinks = []string{
	`https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/router#network_id`,
}

var terraformNoCommonPrivateRouterRemediationMarkdown = ``
