package builtin.aws.neptune.aws0214

test_detects_when_decrypted {
	r := deny with input as {"aws": {"neptune": {"clusters": [{"kmskeyid": {"value": ""}}]}}}
	count(r) == 1
}

test_when_encrypted {
	r := deny with input as {"aws": {"neptune": {"clusters": [{"kmskeyid": {"value": "key12"}}]}}}
	count(r) == 0
}
