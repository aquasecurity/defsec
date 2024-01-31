package builtin.aws.elasticsearch.aws0199

test_detects_when_disabled {
	r := deny with input as {"aws": {"elasticsearch": {"domains": [{"atrestencryption": {"enabled": {"value": false}}}]}}}
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"elasticsearch": {"domains": [{"atrestencryption": {"enabled": {"value": true}}}]}}}
	count(r) == 0
}
