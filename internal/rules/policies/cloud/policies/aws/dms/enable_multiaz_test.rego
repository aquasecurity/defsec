package builtin.aws.dms.aws0318

test_detects_when_disabled {
	r := deny with input as {"aws": {"dms": {"replicationinstances": [{"multiaz": {"value": false}}]}}}
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"dms": {"replicationinstances": [{"multiaz": {"value": true}}]}}}
	count(r) == 0
}
