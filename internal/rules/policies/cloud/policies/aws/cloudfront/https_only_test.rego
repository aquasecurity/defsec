package builtin.aws.cloudfront.aws0313

test_detects_when_not_only_https{
	r := deny with input as {"aws": {"cloudfront": {"distributions": [{"defaultcachebehaviour": {"viewerprotocolpolicy": {"value": "allow-all"}}}]}}}
	count(r) == 1
}

test_when_https_only {
	r := deny with input as {"aws": {"cloudfront": {"distributions": [{"defaultcachebehaviour": {"viewerprotocolpolicy": {"value": "redirect-to-https"}}}]}}}
	count(r) == 0
}
