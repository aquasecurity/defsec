package builtin.aws.apigateway.aws0312

test_detects_when_secure_tls{
	r := deny with input as {"aws": {"apigateway": {"v2": {"domainnames": [{"securitypolicy": {"value": "TLS_1_2"}}]}}}}
	count(r) == 0
}

test_when_not_secure_tls {
	r := deny with input as {"aws": {"apigateway": {"v2": {"domainnames": [{"securitypolicy": {"value": "TLS_1_1"}}]}}}}
	count(r) == 1
}
