package builtin.aws.msk.aws0303

test_detects_when_disabled{
	r := deny with input as {"aws": {"msk": {"clusters": [{"clientauthentication": {"unauthenticated": {"enabled": {"value": false}}}}]}}}
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"msk": {"clusters": [{"clientauthentication": {"unauthenticated": {"enabled": {"value": true}}}}]}}}
	count(r) == 0
}
