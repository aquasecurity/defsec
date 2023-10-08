package builtin.aws.dms.aws0319

test_detects_when_has_no_public_accessible {
	r := deny with input as {"aws": {"dms": {"replicationinstances": [{"publiclyaccessible": {"value": false}}]}}}
	count(r) == 0
}

test_when_has_public_accessible{
	r := deny with input as {"aws": {"dms": {"replicationinstances": [{"publiclyaccessible": {"value": true}}]}}}
	count(r) == 1
}
