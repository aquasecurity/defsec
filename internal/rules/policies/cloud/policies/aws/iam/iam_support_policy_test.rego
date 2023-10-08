package builtin.aws.iam.aws0330

test_detects_has_not_support_policy {
	r := deny with input as {"aws": {"iam": {"policies": [{"name": {"value": "AWSSupportAccess"}}]}}}
	count(r) == 0
}

test_when_has_support_policy {
	r := deny with input as {"aws": {"iam": {"policies": [{"name": {"value": "s3-migration"}}]}}}
	count(r) == 1
}
