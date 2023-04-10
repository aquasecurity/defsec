package network

var terraformAddSecurityGroupToRouterGoodExamples = []string{
	`
 resource "nifcloud_router" "good_example" {
   security_group  = nifcloud_security_group.example.group_name

   network_interface {
     network_id = "net-COMMON_GLOBAL"
   }
 }
 `,
}

var terraformAddSecurityGroupToRouterBadExamples = []string{
	`
 resource "nifcloud_router" "bad_example" {
   security_group  = ""

   network_interface {
     network_id = "net-COMMON_GLOBAL"
   }
 }
 `,
}

var terraformAddSecurityGroupToRouterLinks = []string{
	`https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/router#security_group`,
}

var terraformAddSecurityGroupToRouterRemediationMarkdown = ``
