package iam

var terraformNoUserAttachedPoliciesGoodExamples = []string{
	`
resource "aws_iam_group" "developers" {
  name = "developers"
  path = "/users/"
}

resource "aws_iam_user" "jim" {
  name = "jim"
}

resource "aws_iam_group_membership" "devteam" {
  name = "developers-team"

  users = [
    aws_iam_user.jim.name,
  ]

  group = aws_iam_group.developers.name
}

resource "aws_iam_group_policy" "ec2policy" {
  name = "test"
  group = aws_iam_group.developers.name

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "ec2:Describe*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}
 			`,
}

var terraformNoUserAttachedPoliciesBadExamples = []string{
	`
resource "aws_iam_user" "jim" {
  name = "jim"
}

resource "aws_iam_user_policy" "ec2policy" {
  name = "test"
  user = aws_iam_user.jim.name

  policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Action": [
        "ec2:Describe*"
      ],
      "Effect": "Allow",
      "Resource": "*"
    }
  ]
}
EOF
}
 			`,
}

var terraformNoUserAttachedPoliciesLinks = []string{
	`https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/iam_user`,
}

var terraformNoUserAttachedPoliciesRemediationMarkdown = ``
