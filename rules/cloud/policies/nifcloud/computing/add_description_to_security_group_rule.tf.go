package computing

var terraformAddDescriptionToSecurityGroupRuleGoodExamples = []string{
	`
 resource "nifcloud_security_group_rule" "good_example" {
   type        = "IN"
   description = "HTTP from VPC"
   from_port   = 80
   to_port     = 80
   protocol    = "TCP"
   cidr_ip     = nifcloud_private_lan.main.cidr_block
 }
 `,
}

var terraformAddDescriptionToSecurityGroupRuleBadExamples = []string{
	`
 resource "nifcloud_security_group_rule" "bad_example" {
   type        = "IN"
   description = ""
   from_port   = 80
   to_port     = 80
   protocol    = "TCP"
   cidr_ip     = nifcloud_private_lan.main.cidr_block
 }

 `,
}

var terraformAddDescriptionToSecurityGroupRuleLinks = []string{
	`https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/security_group_rule#description`,
}

var terraformAddDescriptionToSecurityGroupRuleRemediationMarkdown = ``
