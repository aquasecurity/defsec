package builtin.aws.redshift.aws0202

test_detects_when_disabled {
	r := deny with input as {"aws": {"redshift": {"clusters": [{"encryption": {"enabled": {"value": false}}}]}}}
	count(r) == 1
}

test_when_missing_kms{
	r := deny with input as {"aws": {"redshift": {"clusters": [{"kmskeyid": {"value": ""}}]}}}
	count(r) == 0
}

test_detects_with_kms{
	r := deny with input as {"aws": {"redshift": {"clusters": [{"kmskeyid": {"value": "key123"}}]}}}
	count(r) == 1
}
