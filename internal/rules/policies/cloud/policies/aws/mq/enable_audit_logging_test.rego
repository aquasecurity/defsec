package builtin.aws.mq.aws0209

test_detects_when_disabled {
	r := deny with input as {"aws": {"mq": {"brokers": [{"logging": {"audit": {"value": false}}}]}}}
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"mq": {"brokers": [{"logging": {"audit": {"value": true}}}]}}}
	count(r) == 0
}
