package builtin.aws.ssm.aws0203

test_detects_when_empty {
	r := deny with input as {"aws": {"ssm": {"secrets": [{"kmskeyid": {"value": ""}}]}}}
	count(r) == 1
}

test_when_default {
	r := deny with input as {"aws": {"ssm": {"secrets": [{"kmskeyid": {"value": "aws/secretsmanager"}}]}}}
	count(r) == 1
}

test_when_not_empty_or_default {
	r := deny with input as {"aws": {"ssm": {"secrets": [{"kmskeyid": {"value": "key123"}}]}}}
	count(r) == 0
}
