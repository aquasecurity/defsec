package nas

var terraformAddDescriptionToNASSecurityGroupGoodExamples = []string{
	`
 resource "nifcloud_nas_security_group" "good_example" {
   group_name  = "app"
   description = "Allow from app traffic"
 }
 `,
}

var terraformAddDescriptionToNASSecurityGroupBadExamples = []string{
	`
 resource "nifcloud_nas_security_group" "bad_example" {
   name        = "app"
   description = ""
 }
 `,
}

var terraformAddDescriptionToNASSecurityGroupLinks = []string{
	`https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/nas_security_group#description`,
}

var terraformAddDescriptionToNASSecurityGroupRemediationMarkdown = ``
