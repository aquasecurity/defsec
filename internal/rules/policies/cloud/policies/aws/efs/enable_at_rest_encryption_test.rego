package builtin.aws.efs.aws0194

test_detects_when_decrypted {
	r := deny with input as {"aws": {"efs": {"filesystems": [{"encrypted": {"value": false}}]}}}
	count(r) == 1
}

test_when_encrypted {
	r := deny with input as {"aws": {"efs": {"filesystems": [{"encrypted": {"value": true}}]}}}
	count(r) == 0
}