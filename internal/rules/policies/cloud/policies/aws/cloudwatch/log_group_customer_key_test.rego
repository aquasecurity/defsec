package builtin.aws.cloudwatch.aws0181

test_detects_when_decrypted {
	r := deny with input as {"aws": {"cloudwatch": {"loggroups": [{"kmskeyid": {"value": ""}}]}}}
	count(r) == 1
}

test_when_encrypted{
	r := deny with input as {"aws": {"cloudwatch": {"loggroups": [{"kmskeyid": {"value": "key12"}}]}}}
	count(r) == 0
}