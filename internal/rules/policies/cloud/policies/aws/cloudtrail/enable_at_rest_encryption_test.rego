package builtin.aws.cloudtrail.aws0180

test_detects_when_decrypted {
	r := deny with input as {"aws": {"cloudtrail": {"trails": [{"kmskeyid": {"value": ""}}]}}}
	count(r) == 1
}

test_when_encrypted {
	r := deny with input as {"aws": {"cloudtrail": {"trails": [{"kmskeyid": {"value": "key12"}}]}}}
	count(r) == 0
}
