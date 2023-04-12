package builtin.aws.iam.aws0332

test_detects_has_no_password_policy {
	r := deny with input as {"aws": {"iam": {"passwordpolicy": {"expirepasswords": {"value": false}}}}}
	count(r) == 1
}

test_when_has_expiration_greater_than_180 {
	r := deny with input as {"aws": {"iam": {"passwordpolicy": {"expirepasswords": {"value": true}, "maxagedays": {"value": 185}}}}}
	count(r) == 1
}

test_when_has_expiration_suitable {
	r := deny with input as {"aws": {"iam": {"passwordpolicy": {"expirepasswords": {"value": true}, "maxagedays": {"value": 90}}}}}
	count(r) == 0
}
