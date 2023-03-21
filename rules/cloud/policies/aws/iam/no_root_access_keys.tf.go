package iam

var terraformNoRootAccessKeysGoodExamples = []string{
	`
resource "aws_iam_access_key" "good_example" {
 	user = "lowprivuser"
}
 			`,
}

var terraformNoRootAccessKeysBadExamples = []string{
	`
resource "aws_iam_access_key" "good_example" {
 	user = "root"
}
 			`,
}

var terraformNoRootAccessKeysLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_access_key`,
}

var terraformNoRootAccessKeysRemediationMarkdown = ``
