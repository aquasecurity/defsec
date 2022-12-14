package builtin.aws.iam.aws0208

test_detects_when_user_has_no_policy{
	r := deny with input as {"aws": {"iam": {"users": [{"policies": []}]}}}
	count(r) == 0
}

test_when_user_has_policy{
	r := deny with input as {"aws": {"iam": {"users": [{"policies": [{"name": {"value": "supplemental-policy"}}]}]}}}
	count(r) == 1
}
