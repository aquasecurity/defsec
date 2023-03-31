package computing

var terraformAddDescriptionToSecurityGroupGoodExamples = []string{
	`
 resource "nifcloud_security_group" "good_example" {
   group_name  = "http"
   description = "Allow inbound HTTP traffic"
 }
 `,
}

var terraformAddDescriptionToSecurityGroupBadExamples = []string{
	`
 resource "nifcloud_security_group" "bad_example" {
   group_name  = "http"
   description = ""
 }
 `,
}

var terraformAddDescriptionToSecurityGroupLinks = []string{
	`https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/security_group#description`,
}

var terraformAddDescriptionToSecurityGroupRemediationMarkdown = ``
