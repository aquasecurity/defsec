package nas

var terraformNoPublicIngressNASSgrGoodExamples = []string{
	`
 resource "nifcloud_nas_security_group" "good_example" {
   rule {
     cidr_ip = "10.0.0.0/16"
   }
 }
 `,
}

var terraformNoPublicIngressNASSgrBadExamples = []string{
	`
 resource "nifcloud_nas_security_group" "bad_example" {
   rule {
     cidr_ip = "0.0.0.0/0"
   }
 }
 `,
}

var terraformNoPublicIngressNASSgrLinks = []string{
	`https://registry.terraform.io/providers/nifcloud/nifcloud/latest/docs/resources/nas_security_group#cidr_ip`,
}

var terraformNoPublicIngressNASSgrRemediationMarkdown = ``
