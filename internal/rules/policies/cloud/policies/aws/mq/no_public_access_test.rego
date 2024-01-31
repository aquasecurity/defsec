package builtin.aws.mq.aws0211

test_detects_when_disabled {
	r := deny with input as {"aws": {"mq": {"brokers": [{"publicaccess": {"value": false}}]}}}
	count(r) == 0
}

test_when_enabled {
	r := deny with input as {"aws": {"mq": {"brokers": [{"publicaccess": {"value": true}}]}}}
	count(r) == 1
}
