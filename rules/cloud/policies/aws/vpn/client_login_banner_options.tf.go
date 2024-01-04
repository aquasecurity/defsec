package vpn

var terraformCheckClientLoginBannerOptionsGoodExamples = []string{
	`
resource "aws_ec2_client_vpn_endpoint" "good_example" {
	client_login_banner_options		= "test-configuration"
}
 `,
}

var terraformCheckClientLoginBannerOptionsBadExamples = []string{
	`
resource "aws_ec2_client_vpn_endpoint" "bad_example" {
	client_login_banner_options		= ""
}
`,
}

var terraformCheckClientLoginBannerOptionsLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/ec2_client_vpn_endpoint#client_login_banner_options`,
}

var terraformCheckClientLoginBannerOptionsRemediationMarkdown = ``
