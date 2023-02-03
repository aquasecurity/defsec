package ec2

var terraformNoPublicIpSubnetGoodExamples = []string{
	`
 resource "aws_subnet" "good_example" {
	vpc_id                  = "vpc-123456"
	map_public_ip_on_launch = false
 }
 `,
}

var terraformNoPublicIpSubnetBadExamples = []string{
	`
 resource "aws_subnet" "bad_example" {
	vpc_id                  = "vpc-123456"
	map_public_ip_on_launch = true
 }
 `,
}

var terraformNoPublicIpSubnetLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/subnet#map_public_ip_on_launch`,
}

var terraformNoPublicIpSubnetRemediationMarkdown = ``
