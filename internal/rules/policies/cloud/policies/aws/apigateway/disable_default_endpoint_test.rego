package builtin.aws.apigateway.aws0308

test_detects_when_disabled {
	r := deny with input as {"aws": {"apigateway": {"v1": {"apis": [{"disableexecuteapiendpoint": {"value": false}}]}}}}
	count(r) == 0
}

test_when_enabled {
	r := deny with input as {"aws": {"apigateway": {"v1": {"apis": [{"disableexecuteapiendpoint": {"value": true}}]}}}}
	count(r) == 1
}
