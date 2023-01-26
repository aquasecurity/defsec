package builtin.aws.autoscaling.aws0339

test_detects_when_more_than_1{
	r := deny with input as {"aws": {"autoscaling": {"autoscalinggroupslist": [{"avaiabilityzone": [{"value": "test-1" }, {"value": "test-2"}]}]}}}
	count(r) == 0
}

test_when_not_more_than_1 {
	r := deny with input as {"aws": {"autoscaling": {"autoscalinggroupslist": [{"avaiabilityzone": [{"value": "test-1"}]}]}}}
	count(r) == 1
}
