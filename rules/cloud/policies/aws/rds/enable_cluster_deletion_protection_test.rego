package builtin.aws.rds.aws0343

test_detects_when_disabled {
	r := deny with input as {"aws": {"rds": {"clusters": [{"deletionprotection": {"value": false}}]}}}
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"rds": {"clusters": [{"deletionprotection": {"value": true}}]}}}
	count(r) == 0
}
