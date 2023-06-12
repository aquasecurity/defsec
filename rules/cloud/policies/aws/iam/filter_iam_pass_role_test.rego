package builtin.aws.iam.aws0342

test_with_allow_iam_pass_role {
	policies := [{
		"name": "policy_with_iam_pass_role",
		"document": {"value": "{\"Version\":\"2012-10-17\",\"Id\":\"\",\"Statement\":[{\"Sid\":\"\",\"Effect\":\"Allow\",\"Principal\":{},\"NotPrincipal\":{},\"Action\":[\"iam:PassRole\"],\"NotAction\":null,\"Resource\":[\"arn:aws:iam::193063503752:role/atc-node\"],\"NotResource\":null,\"Condition\":{}}]}"},
	}]
	r := deny with input as {"aws": {"iam": {"policies": policies}}}
	count(r) == 1
}

test_with_deny_iam_pass_role {
	policies := [{
		"name": "policy_with_iam_pass_role",
		"document": {"value": "{\"Version\":\"2012-10-17\",\"Id\":\"\",\"Statement\":[{\"Sid\":\"\",\"Effect\":\"Deny\",\"Principal\":{},\"NotPrincipal\":{},\"Action\":[\"iam:PassRole\"],\"NotAction\":null,\"Resource\":[\"arn:aws:iam::193063503752:role/atc-node\"],\"NotResource\":null,\"Condition\":{}}]}"},
	}]
	r := deny with input as {"aws": {"iam": {"policies": policies}}}
	count(r) == 0
}

test_with_no_iam_pass_role {
	policies := [{
		"name": "policy_without_iam_pass_role",
		"document": {"value": "{\"Version\":\"2012-10-17\",\"Id\":\"\",\"Statement\":[{\"Sid\":\"\",\"Effect\":\"Allow\",\"Principal\":{},\"NotPrincipal\":{},\"Action\":[\"s3:GetObject\"],\"NotAction\":null,\"Resource\":[\"arn:aws:s3:::examplebucket/*\"],\"NotResource\":null,\"Condition\":{}}]}"},
	}]
	r := deny with input as {"aws": {"iam": {"policies": policies}}}
	count(r) == 0
}
