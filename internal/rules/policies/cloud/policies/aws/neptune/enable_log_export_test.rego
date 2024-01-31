package builtin.aws.neptune.aws0212

test_detects_when_disabled {
	r := deny with input as {"aws": {"neptune": {"clusters": [{"logging": {"audit": {"value": false}}}]}}}
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"neptune": {"clusters": [{"logging": {"audit": {"value": true}}}]}}}
	count(r) == 0
}
