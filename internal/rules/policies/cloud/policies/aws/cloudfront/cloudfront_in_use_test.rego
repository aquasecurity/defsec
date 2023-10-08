package builtin.aws.cloudfront.aws0314

test_detects_when_cloudfront_in_use{
	r := deny with input as {"aws": {"cloudfront": {"distributions": [{"defaultcachebehaviour": {"viewerprotocolpolicy": {"value": "allow-all"}}}]}}}
	count(r) == 0
}

test_when_cloudfront_not_in_use {
	r := deny with input as {"aws": {"cloudfront": {"distributions": []}}}
	count(r) == 1
}
