package builtin.aws.autoscaling.aws0340

test_detects_when_have_instances {
	r := deny with input as {"aws": {"autoscaling": {"autoscalinggroupslist": [{"instances": [{"instanceid": {"value": "test-1"}}]}]}}}
	count(r) == 0
}

test_when_have_no_instances {
	r := deny with input as {"aws": {"autoscaling": {"autoscalinggroupslist": [{}]}}}
	count(r) == 1
}
