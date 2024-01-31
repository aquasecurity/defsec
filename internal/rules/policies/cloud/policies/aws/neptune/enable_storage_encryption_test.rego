package builtin.aws.neptune.aws0213

test_detects_when_disabled {
	r := deny with input as {"aws": {"neptune": {"clusters": [{"storageencrypted": {"value": false}}]}}}
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"neptune": {"clusters": [{"storageencrypted": {"value": true}}]}}}
	count(r) == 0
}
