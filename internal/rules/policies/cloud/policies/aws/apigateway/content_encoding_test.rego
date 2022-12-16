package builtin.aws.apigateway.aws0219

test_detects_when_disabled {
	r := deny with input as {"aws": {"apigateway": {"v1": {"apis": [{}]}}}}
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"apigateway": {"v1": {"apis": [{"minimumcompressionsize": {"value": 12}}]}}}}
	count(r) == 0
}
