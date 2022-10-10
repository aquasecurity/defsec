package builtin.aws.rds.aws0177

test_detects_when_disabled {
	r := deny with input as {"aws": {"rds": {"instances": [{"deletionprotection": {"value": false}}]}}}
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"rds": {"instances": [{"deletionprotection": {"value": true}}]}}}
	count(r) == 0
}
