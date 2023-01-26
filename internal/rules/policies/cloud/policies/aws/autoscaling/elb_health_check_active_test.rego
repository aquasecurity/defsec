package builtin.aws.autoscaling.aws0341

test_detects_when_elb_active{
	r := deny with input as {"aws": {"autoscaling": {"autoscalinggroupslist": [{"healthchecktype": {"value": "ELB"}},
                                                                               {}]}}}
	count(r) == 0
}

test_when_elb_not_active {
	r := deny with input as {"aws": {"autoscaling": {"autoscalinggroupslist": [{"healthchecktype": {"value": "EC2"}},
                                                                               {"loadbalancernames":[{"name": {"value": "test"}}]}]}}}
	count(r) == 1
}
