package builtin.aws.lambda.aws0305

test_detects_when_has_vpc {
	r := deny with input as {"aws": {"lambda": {"functions": [{"vpcconfig": {"vpcid": {"value": "vpc1234"}}}]}}}
	count(r) == 0
}

test_when_has_no_vpc {
	r := deny with input as {"aws": {"lambda": {"functions": [{"vpcconfig": {"vpcid": {"value": ""}}}]}}}
	count(r) == 1
}
