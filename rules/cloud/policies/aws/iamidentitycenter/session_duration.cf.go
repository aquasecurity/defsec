package iamidentitycenter

var cloudFormationSessionDurationGoodExamples = []string{
	`---
Type: AWS::SSO::PermissionSet
Properties:
	Description: "An example"
	InstanceArn: String
	Name: "Example"
	SessionDuration: "PT2H"
`,
}

var cloudFormationSessionDurationBadExamples = []string{
	`---
Type: AWS::SSO::PermissionSet
Properties:
	Description: "An example"
	InstanceArn: String
	Name: "Example"
	SessionDuration: ""
`,
}

var cloudFormationSessionDurationLinks = []string{
	`https://docs.aws.amazon.com/AWSCloudFormation/latest/UserGuide/aws-resource-sso-permissionset.html#cfn-sso-permissionset-sessionduration`,
}

var cloudFormationSessionDurationRemediationMarkdown = ``
