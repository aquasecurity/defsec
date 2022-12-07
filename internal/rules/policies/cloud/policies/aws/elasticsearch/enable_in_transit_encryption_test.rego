package builtin.aws.elasticsearch.aws0205

test_detects_when_disabled {
	r := deny with input as {"aws": {"elasticsearch": {"domains": [{"transitencryption": {"enabled": {"value": false}}}]}}}
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"elasticsearch": {"domains": [{"transitencryption": {"enabled": {"value": true}}}]}}}
	count(r) == 0
}
