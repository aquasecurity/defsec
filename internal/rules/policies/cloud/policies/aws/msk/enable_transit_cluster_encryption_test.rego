package builtin.aws.msk.aws0302

test_detects_when_disabled{
	r := deny with input as {"aws": {"msk": {"clusters": [{"encryptionintransit": {"incluster": {"value": false}}}]}}}
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"msk": {"clusters": [{"encryptionintransit": {"incluster": {"value": true}}}]}}}
	count(r) == 0
}
