package builtin.aws.ecr.aws0192

test_detects_when_mutable {
	r := deny with input as {"aws": {"ecr": {"repositories": [{"imagetagsimmutable": {"value": false}}]}}}
	count(r) == 1
}

test_when_immutable {
	r := deny with input as {"aws": {"ecr": {"repositories": [{"imagetagsimmutable": {"value": true}}]}}}
	count(r) == 0
}