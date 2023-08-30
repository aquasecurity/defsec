package builtin.aws.s3.aws0089

test_detects_when_disabled {
	r := deny with input as {"aws": {"s3": {"buckets": [{"logging": {"enabled": {"value": false}}}]}}}
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"s3": {"buckets": [{"logging": {"enabled": {"value": true}}}]}}}
	count(r) == 0
}

test_detects_when_disabled_but_acl_is_log_write {
	r := deny with input as {"aws": {"s3": {"buckets": [{
		"logging": {"enabled": {"value": false}},
		"acl": {"value": "log-delivery-write"},
	}]}}}
	count(r) == 0
}

test_detects_when_enabled_and_acl_is_not_log_write {
	r := deny with input as {"aws": {"s3": {"buckets": [{
		"logging": {"enabled": {"value": false}},
		"acl": {"value": "private"},
	}]}}}
	count(r) == 1
}
