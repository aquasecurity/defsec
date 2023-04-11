package builtin.aws.iam.aws0336

test_detects_not_requires_symbols {
	r := deny with input as {"aws": {"iam": {"passwordpolicy": {"requiresymbols": {"value": false}}}}}
	count(r) == 1
}

test_detects_requires_symbols {
	r := deny with input as {"aws": {"iam": {"passwordpolicy": {"requiresymbols": {"value": true}}}}}
	count(r) == 0
}
