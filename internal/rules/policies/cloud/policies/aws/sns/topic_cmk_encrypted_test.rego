package builtin.aws.sns.aws0300

test_detects_when_disabled {
	r := deny with input as {"aws": {"sns": {"topics": [{"encryption": {"kmskeyid": {"value": ""}}}]}}}
	count(r) == 1
}

test_when_enabled_or_default {
	r := deny with input as {"aws": {"sns": {"topics": [{"encryption": {"kmskeyid": {"value": "alias/aws/sns"}}}]}}}
	count(r) == 1
}

test_when_enabled_or_not_default {
	r := deny with input as {"aws": {"sns": {"topics": [{"encryption": {"kmskeyid": {"value": "key12"}}}]}}}
	count(r) == 0
}
