package builtin.aws.cloudtrail.aws0200

test_detects_when_disabled {
	r := deny with input as {"aws": {"cloudtrail": {"trails": [{"includeglobalserviceevents": {"value": false}}]}}}
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"cloudtrail": {"trails": [{"includeglobalserviceevents": {"value": true}}]}}}
	count(r) == 0
}
