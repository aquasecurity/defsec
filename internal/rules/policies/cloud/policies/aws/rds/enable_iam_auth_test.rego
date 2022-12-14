package builtin.aws.rds.aws0176

test_detects_when_disabled {
	r := deny with input as {"aws": {"rds": {"instances": [{
		"engine": {"value": "postgres"},
		"iamauthenabled": {"value": false},
	}]}}}

	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"rds": {"instances": [{
		"engine": {"value": "postgres"},
		"iamauthenabled": {"value": true},
	}]}}}

	count(r) == 0
}

test_when_not_applicable {
	r := deny with input as {"aws": {"rds": {"instances": [{
		"engine": {"value": "aurora"},
		"iamauthenabled": {"value": false},
	}]}}}

	count(r) == 0
}
