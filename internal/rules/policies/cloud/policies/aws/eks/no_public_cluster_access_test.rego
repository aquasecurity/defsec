package builtin.aws.eks.aws0195

test_detects_when_disabled {
	r := deny with input as {"aws": {"eks": {"clusters": [{"publicaccessenabled": {"value": false}}]}}}
	count(r) == 0
}

test_when_enabled {
	r := deny with input as {"aws": {"eks": {"clusters": [{"publicaccessenabled": {"value": true}}]}}}
	count(r) == 1
}