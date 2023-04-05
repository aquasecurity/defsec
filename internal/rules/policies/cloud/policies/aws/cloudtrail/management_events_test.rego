package builtin.aws.cloudtrail.aws0327

test_detects_when_management_events_configured {
	r := deny with input as {"aws": {"cloudtrail": {"trails": [{"eventselectors": [{"includemanagementevents":  {"value": true}}]}]}}}
	count(r) == 0
}

test_when_management_events_not_configured {
	r := deny with input as {"aws": {"cloudtrail": {"trails": [{"eventselectors": [{"includemanagementevents":  {"value": false}}]}]}}}
	count(r) == 1
}
