package builtin.aws.cloudtrail.aws0182

test_detects_when_not_configured {
	r := deny with input as {"aws": {"cloudtrail": {"trails": [{"cloudwatchlogsloggrouparn": {"value": ""}}]}}}
	count(r) == 1
}

test_when_configured {
	r := deny with input as {"aws": {"cloudtrail": {"trails": [{"cloudwatchlogsloggrouparn": {"value": "arn:aws:logs:us-east-1:123456789012:log-group:my-log-group"}}]}}}
	count(r) == 0
}
