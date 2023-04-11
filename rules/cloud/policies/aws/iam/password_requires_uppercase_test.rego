package builtin.aws.iam.aws0335

test_detects_not_requires_uppercase {
	r := deny with input as {"aws": {"iam": {"passwordpolicy": {"requireuppercase": {"value": false}}}}}
	count(r) == 1
}

test_detects_requires_uppercase {
	r := deny with input as {"aws": {"iam": {"passwordpolicy": {"requireuppercase": {"value": true}}}}}
	count(r) == 0
}
