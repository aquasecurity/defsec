package builtin.aws.mq.aws0210

test_detects_when_disabled {
	r := deny with input as {"aws": {"mq": {"brokers": [{"logging": {"general": {"value": false}}}]}}}
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"mq": {"brokers": [{"logging": {"general": {"value": true}}}]}}}
	count(r) == 0
}
