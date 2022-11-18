package builtin.aws.cloudfront.aws0181

test_unsecure_tls_policy {
	r := deny with input as {"aws": {"cloudfront": {"distributions": [{"viewercertificate": {"minimumprotocolversion": {"value": "TLSv1.0"}}}]}}}
	count(r) == 1
}

test_secure_tls_policy {
	r := deny with input as {"aws": {"cloudfront": {"distributions": [{"viewercertificate": {"minimumprotocolversion": {"value": "TLSv1.2_2021"}}}]}}}
	count(r) == 0
}