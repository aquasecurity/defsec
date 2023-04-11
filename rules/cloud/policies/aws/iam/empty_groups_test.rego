package builtin.aws.iam.aws0329

test_detects_not_empty_group {
	r := deny with input as {"aws": {"iam": {"groups": [{"users": [{"name": {"value": "user"}}]}]}}}
	count(r) == 0
}

test_when_empty_group {
	r := deny with input as {"aws": {"iam": {"groups": [{}]}}}
	count(r) == 1
}
