package builtin.aws.elasticache.aws0197

test_detects_when_disabled {
	r := deny with input as {"aws": {"elasticache": {"replicationgroups": [{"atrestencryptionenabled": {"value": false}}]}}}
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"elasticache": {"replicationgroups": [{"atrestencryptionenabled": {"value": true}}]}}}
	count(r) == 0
}