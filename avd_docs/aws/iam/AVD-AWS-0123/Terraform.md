
Use terraform-module/enforce-mfa/aws to ensure that MFA is enforced

```hcl
resource "aws_iam_group" "support" {
  name =  "support"
}
resource aws_iam_group_policy mfa {
   
    group = aws_iam_group.support.name
    policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Action": "ec2:*",
      "Resource": "*",
      "Condition": {
          "Bool": {
              "aws:MultiFactorAuthPresent": ["true"]
          }
      }
    }
  ]
}
EOF
}

```
```hcl
resource "aws_iam_group" "support" {
  name =  "support"
}
resource aws_iam_policy mfa {
   
    name = "something"
    policy = <<EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "",
      "Effect": "Allow",
      "Action": "ec2:*",
      "Resource": "*",
      "Condition": {
          "Bool": {
              "aws:MultiFactorAuthPresent": ["true"]
          }
      }
    }
  ]
}
EOF
}
resource aws_iam_group_policy_attachment attach {
    group = aws_iam_group.support.name
    policy_arn = aws_iam_policy.mfa.id
}

```
```hcl
resource "aws_iam_group" "support" {
  name =  "support"
}
resource aws_iam_group_policy mfa {
  group = aws_iam_group.support.name
  policy = data.aws_iam_policy_document.combined.json
}
data "aws_iam_policy_document" "policy_override" {
  statement {
    sid    = "main"
    effect = "Allow"
    actions   = ["s3:*"]
    resources = ["*"]
    condition {
        test = "Bool"
        variable = "aws:MultiFactorAuthPresent"
        values = ["true"]
    }
  }
}
data "aws_iam_policy_document" "policy_source" {
  statement {
    sid    = "main"
    effect = "Allow"
    actions   = ["iam:*"]
    resources = ["*"]
  }
}
data "aws_iam_policy_document" "policy_misc" {
  statement {
    sid    = "misc"
    effect = "Deny"
    actions   = ["logs:*"]
    resources = ["*"]
  }
}
data "aws_iam_policy_document" "combined" {
  source_json = <<EOF
    {
        "Id": "base"
    }
EOF
  source_policy_documents = [
    data.aws_iam_policy_document.policy_source.json
  ]
  override_policy_documents = [
    data.aws_iam_policy_document.policy_override.json,
    data.aws_iam_policy_document.policy_misc.json
  ]
  statement {
    sid    = "whatever"
    effect = "Deny"
    actions   = ["*"]
    resources = ["*"]
  }
}

```

#### Remediation Links
 - https://registry.terraform.io/modules/terraform-module/enforce-mfa/aws/latest

 - https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_passwords_account-policy.html#password-policy-details

