package builtin.aws.cloudtrail.aws0324

test_detects_when_data_events_configured {
	r := deny with input as {"aws": {"cloudtrail": {"trails": [{"eventselectors": [{"dataresources": [{"type": {"value": "AWS::S3::Object"}}]}]}]}}}
	count(r) == 0
}

test_when_data_events_not_configured {
	r := deny with input as {"aws": {"cloudtrail": {"trails": [{"eventselectors": [{}]}]}}}
	count(r) == 1
}
