package builtin.aws.elasticsearch.aws0206

test_detects_when_not_enforce_https {
	r := deny with input as {"aws": {"elasticsearch": {"domains": [{"endpoint": {"enforcehttps": {"value": false}}}]}}}
	count(r) == 1
}

test_when_enforce_https {
	r := deny with input as {"aws": {"elasticsearch": {"domains": [{"endpoint": {"enforcehtttps": {"value": true}}}]}}}
	count(r) == 0
}
