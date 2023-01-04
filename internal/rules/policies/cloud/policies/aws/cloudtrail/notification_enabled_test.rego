package builtin.aws.cloudtrail.aws0325

test_detects_when_has_ative_sns_topic {
	r := deny with input as {"aws": {"cloudtrail": {"trails": [{"snstopicname": {"value": "arn123"}}]},
                                      "sns": {"topics": [{"arn": {"value": "arn123"}}]}}}
	count(r) == 0
}

test_when_has_not_active_sns_topic {
	r := deny with input as {"aws": {"cloudtrail": {"trails": [{"snstopicname": {"value": "arn123"}}]},
                                    "sns": {"topics": [{"arn": {"value": "arn456"}}]}}}
	count(r) == 1
}
