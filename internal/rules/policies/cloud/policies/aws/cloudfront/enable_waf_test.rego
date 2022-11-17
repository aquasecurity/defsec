package builtin.aws.cloudfront.aws0180

test_detects_when_disabled {
	r := deny with input as {"aws": {"cloudfront": {"distributions": [{"wafid": {"value": ""}}]}}}
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"cloudfront": {"distributions": [{"wafid": {"value": "waf12"}}]}}}
	count(r) == 0
}