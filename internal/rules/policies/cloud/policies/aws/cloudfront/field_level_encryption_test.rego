package builtin.aws.cloudfront.aws0315

test_detects_when_disabled{
	r := deny with input as {"aws": {"cloudfront": {"distributions": [{"defaultcachebehaviour": {"fieldlevelencryptionid": {"value": ""}}}]}}}
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"cloudfront": {"distributions": [{"defaultcachebehaviour": {"fieldlevelencryptionid": {"value": "testid"}}}]}}}
	count(r) == 0
}
