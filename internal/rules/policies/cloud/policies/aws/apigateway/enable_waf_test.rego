package builtin.aws.apigateway.aws0310

test_detects_when_disabled {
	r := deny with input as {"aws": {"apigateway": {"v1": {"apis": [{"stages": [{"webaclarn": {"value": ""}}]}]}}}}
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"apigateway": {"v1": {"apis": [{"stages": [{"webaclarn": {"value": "arn"}}]}]}}}}
	count(r) == 0
}
