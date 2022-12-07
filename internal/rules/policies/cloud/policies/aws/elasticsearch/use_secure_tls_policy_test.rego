package builtin.aws.elasticsearch.aws0207

test_detects_when_not_secure {
	r := deny with input as {"aws": {"elasticsearch": {"domains": [{"endpoint": {"tlspolicy": {"value": "Policy-Min-TLS-1-1-2019-07"}}}]}}}
	count(r) == 1
}

test_when_secure {
	r := deny with input as {"aws": {"elasticsearch": {"domains": [{"endpoint": {"tlspolicy": {"value": "Policy-Min-TLS-1-2-2019-07"}}}]}}}
	count(r) == 0
}
