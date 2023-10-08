package builtin.aws.iam.aws0331

test_detects_has_users{
	r := deny with input as {"aws": {"iam": {"users": [{"name": {"value": "user"}}]}}}
	count(r) == 0
}

test_when_has_no_user{
	r := deny with input as {"aws": {"iam": {"users": []}}}
	count(r) == 1
}
