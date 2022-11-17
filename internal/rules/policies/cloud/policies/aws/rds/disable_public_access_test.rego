package builtin.aws.rds.aws0180

test_detects_when_disabled {
	r := deny with input as {"aws": {"rds": {"instances": [{"publicaccess": {"value": false}}]}}}
	count(r) == 0
}

test_when_enabled {
	r := deny with input as {"aws": {"rds": {"instances": [{"publicaccess": {"value": true}}]}}}
	count(r) == 1
}
