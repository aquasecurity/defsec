package builtin.aws.dms.aws0317

test_detects_when_disabled {
	r := deny with input as {"aws": {"dms": {"replicationinstances": [{"autominorversionupgrade": {"value": false}}]}}}
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"dms": {"replicationinstances": [{"autominorversionupgrade": {"value": true}}]}}}
	count(r) == 0
}
