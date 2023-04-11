package builtin.aws.iam.aws0333

test_detects_not_requires_lowercase {
	r := deny with input as {"aws": {"iam": {"passwordpolicy": {"requirelowercase": {"value": false}}}}}
	count(r) == 1
}

test_detects_requires_lowercase {
	r := deny with input as {"aws": {"iam": {"passwordpolicy": {"requirelowercase": {"value": true}}}}}
	count(r) == 0
}
