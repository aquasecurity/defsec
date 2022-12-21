package builtin.aws.apigateway.aws0307

test_detects_when_disabled {
	r := deny with input as {"aws": {"apigateway": {"v1": {"apis": [{"stages": [{"xraytracingenabled": {"value": false}}]}]}}}}
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"apigateway": {"v1": {"apis": [{"stages": [{"xraytracingenabled": {"value": true}}]}]}}}}
	count(r) == 0
}
