package builtin.aws.s3.aws0321

test_detects_when_disabled {
	r := deny with input as {"aws": {"s3": {"buckets": [{"logging": {"enabled": {"value": false}}}]}}}
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"s3": {"buckets": [{"logging": {"enabled": {"value": true}}}]}}}
	count(r) == 0
}
