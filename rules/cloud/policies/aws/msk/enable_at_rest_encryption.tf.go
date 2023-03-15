package msk

var terraformEnableAtRestEncryptionGoodExamples = []string{
	`
 resource "aws_msk_cluster" "good_example" {
 	encryption_info {
		encryption_at_rest_kms_key_arn = "foo-bar-key"
 	}
 }
 `,
}

var terraformEnableAtRestEncryptionBadExamples = []string{
	`
 resource "aws_msk_cluster" "bad_example" {
 	encryption_info {
 	}
 }
 `,
}

var terraformEnableAtRestEncryptionLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/msk_cluster#encryption_info-argument-reference`,
}

var terraformEnableAtRestEncryptionRemediationMarkdown = ``
