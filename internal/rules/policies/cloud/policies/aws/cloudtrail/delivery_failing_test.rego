package builtin.aws.cloudtrail.aws0328

test_detects_when_not_delivered {
	r := deny with input as {"aws": {"cloudtrail": {"trails": [{"latestdeliveryerror": {"value": "erroroccur"}}]}}}
	count(r) == 1
}

test_when_delivered {
	r := deny with input as {"aws": {"cloudtrail": {"trails": [{}]}}}
	count(r) == 0
}
