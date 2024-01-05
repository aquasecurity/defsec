package iamidentitycenter

var terraformSessionDurationGoodExamples = []string{
	`
	data "aws_ssoadmin_instances" "example" {}

	resource "aws_ssoadmin_permission_set" "example" {
		name             = "Example"
		description      = "An example"
		instance_arn     = tolist(data.aws_ssoadmin_instances.example.arns)[0]
		session_duration = "PT2H"
	  }
`,
}

var terraformSessionDurationBadExamples = []string{
	`
	data "aws_ssoadmin_instances" "example" {}

	resource "aws_ssoadmin_permission_set" "example" {
		name             = "Example"
		description      = "An example"
		instance_arn     = tolist(data.aws_ssoadmin_instances.example.arns)[0]
		session_duration = ""
	  }
`,
}

var terraformSessionDurationLinks = []string{
	`https://docs.aws.amazon.com/AWSterraform/latest/UserGuide/aws-resource-sso-permissionset.html#cfn-sso-permissionset-sessionduration`,
}

var terraformSessionDurationRemediationMarkdown = ``
