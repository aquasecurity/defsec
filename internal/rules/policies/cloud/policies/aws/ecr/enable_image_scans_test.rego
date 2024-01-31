package builtin.aws.ecr.aws0191

test_detects_when_disabled {
	r := deny with input as {"aws": {"ecr": {"repositories": [{"imagescanning": {"scanonpush": {"value": false}}}]}}}
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"ecr": {"repositories": [{"imagescanning": {"scanonpush": {"value": true}}}]}}}
	count(r) == 0
}