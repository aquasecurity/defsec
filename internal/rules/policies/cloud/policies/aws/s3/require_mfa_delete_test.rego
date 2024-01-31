package builtin.aws.s3.aws0217

test_detects_when_disabled {
	r := deny with input as {"aws": {"s3": {"buckets": [{"versioning": {"mfadelete": {"value": false}}}]}}}
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"s3": {"buckets": [{"versioning": {"mfadelete": {"value": true}}}]}}}
	count(r) == 0
}
