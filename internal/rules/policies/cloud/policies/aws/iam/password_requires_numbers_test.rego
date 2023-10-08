package builtin.aws.iam.aws0334

test_detects_not_requires_numbers {
	r := deny with input as {"aws": {"iam": {"passwordpolicy": {"requirenumbers": {"value": false}}}}}
	count(r) == 1
}

test_detects_requires_numbers {
	r := deny with input as {"aws": {"iam": {"passwordpolicy": {"requirenumbers": {"value": true}}}}}
	count(r) == 0
}
