package builtin.aws.documentdb.aws0189

test_detects_when_decrypted {
	r := deny with input as {"aws": {"documentdb": {"clusters": [{"storageencrypted": {"value": false}}]}}}
	count(r) == 1
}

test_when_encrypted {
	r := deny with input as {"aws": {"documentdb": {"clusters": [{"storageencrypted": {"value": true}}]}}}
	count(r) == 0
}