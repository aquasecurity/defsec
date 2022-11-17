package builtin.aws.cloudfront.aws0184

test_detects_when_disabled {
	r := deny with input as {"aws": {"cloudfront": {"distributions": [{"logging":{"bucket": {"value": ""}}}]}}}
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"cloudfront": {"distributions": [{"logging":{"bucket": {"value": "myvalue"}}}]}}}
	count(r) == 0
}
