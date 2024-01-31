package builtin.aws.ecs.aws0193

test_detects_when_disabled {
	r := deny with input as {"aws": {"ecs": {"clusters": [{"settings": {"containerinsightsenabled": {"value": false}}}]}}}
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"ecs": {"clusters": [{"settings": {"containerinsightsenabled": {"value": true}}}]}}}
	count(r) == 0
}