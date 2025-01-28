package builtin.aws.ec2.aws0183

test_detects_when_not_default{
	r := deny with input as {"aws": {"ec2": {"vpcs": [{"isdefault": {"value": false}}]}}}
	count(r) == 0
}

test_when_default {
	r := deny with input as {"aws": {"ec2": {"vpcs": [{"isdefault": {"value": true}}]}}}
	count(r) == 1
}