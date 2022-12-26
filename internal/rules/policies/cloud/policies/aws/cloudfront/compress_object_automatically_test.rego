package builtin.aws.cloudfront.aws0316

test_detects_when_not_configure_compress_files{
	r := deny with input as {"aws": {"cloudfront": {"distributions": [{"defaultcachebehaviour": {"compress": {"value": false}}}]}}}
	count(r) == 1
}

test_when_configure_compress_files {
	r := deny with input as {"aws": {"cloudfront": {"distributions": [{"defaultcachebehaviour": {"compress": {"value": true}}}]}}}
	count(r) == 0
}
