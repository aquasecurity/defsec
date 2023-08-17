package builtin.aws.s3.aws0320

test_detects_when_has_not_dns_compliant_name {
	r := deny with input as {"aws": {"s3": {"buckets": [{"name": {"value": "sana.test"}}]}}}
	count(r) == 1
}

test_when_has_dns_compliant_name {
	r := deny with input as {"aws": {"s3": {"buckets": [{"name": {"value": "sana-test"}}]}}}
	count(r) == 0
}
