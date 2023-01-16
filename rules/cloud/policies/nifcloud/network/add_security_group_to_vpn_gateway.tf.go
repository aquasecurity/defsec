package network

var terraformAddSecurityGroupToVpnGatewayGoodExamples = []string{
	`
 resource "nifcloud_vpn_gateway" "good_example" {
   security_group  = nifcloud_security_group.example.group_name

   network_interface {
     network_id = "net-COMMON_GLOBAL"
   }
 }
 `,
}

var terraformAddSecurityGroupToVpnGatewayBadExamples = []string{
	`
 resource "nifcloud_vpn_gateway" "bad_example" {
   security_group  = ""

   network_interface {
     network_id = "net-COMMON_GLOBAL"
   }
 }
 `,
}

var terraformAddSecurityGroupToVpnGatewayLinks = []string{
	`https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/vpn_gateway#security_group`,
}

var terraformAddSecurityGroupToVpnGatewayRemediationMarkdown = ``
