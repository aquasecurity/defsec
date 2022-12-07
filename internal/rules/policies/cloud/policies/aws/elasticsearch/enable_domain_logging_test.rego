package builtin.aws.elasticsearch.aws0204

test_detects_when_disabled {
	r := deny with input as {"aws": {"elasticsearch": {"domains": [{"logpublishing": {"auditenabled": {"value": false}}}]}}}
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"elasticsearch": {"domains": [{"logpublishing": {"auditenabled": {"value": true}}}]}}}
	count(r) == 0
}

