package builtin.aws.msk.aws0301

test_detects_when_allow_plaintext{
	r := deny with input as {"aws": {"msk": {"clusters": [{"encryptionintransit": {"clientbroker": {"value": "PLAINTEXT"}}}]}}}
	count(r) == 1
}

test_when_not_allow_plaintext {
	r := deny with input as {"aws": {"msk": {"clusters": [{"encryptionintransit": {"clientbroker": {"value": "TLS"}}}]}}}
	count(r) == 0
}
