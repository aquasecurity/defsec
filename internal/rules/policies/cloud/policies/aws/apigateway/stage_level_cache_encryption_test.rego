package builtin.aws.apigateway.aws0309

test_detects_when_encrypted_cache_data {
	r := deny with input as {"aws": {"apigateway": {"v1": {"apis": [{"stages": [{"restmethodsettings": [{"cacheenabled": {"value": true}, "cachedataencrypted": {"value": true}}]}]}]}}}}
	count(r) == 0
}

test_when_not_encrypted_cache_data {
	r := deny with input as {"aws": {"apigateway": {"v1": {"apis": [{"stages": [{"restmethodsettings": [{"cacheenabled": {"value": true}, "cachedataencrypted": {"value": false}}]}]}]}}}}
	count(r) == 1
}
