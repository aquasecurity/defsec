package builtin.aws.cloudtrail.aws0181

test_detects_when_disabled {
	r := deny with input as {"aws": {"cloudtrail": {"trails": [{"enablelogfilevalidation": {"value": false}}]}}}
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"cloudtrail": {"trails": [{"enablelogfilevalidation": {"value": true}}]}}}
	count(r) == 0
}
