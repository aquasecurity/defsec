package ec2

var terraformASEnableAtRestEncryptionGoodExamples = []string{
	`
 resource "aws_launch_configuration" "good_example" {
 	root_block_device {
 		encrypted = true
 	}
 }
 `,
}

var terraformASEnableAtRestEncryptionBadExamples = []string{
	`
 resource "aws_launch_configuration" "bad_example" {
 	root_block_device {
 		encrypted = false
 	}
 }
 `,
}

var terraformASEnableAtRestEncryptionLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/instance#ebs-ephemeral-and-root-block-devices`,
}

var terraformASEnableAtRestEncryptionRemediationMarkdown = ``
