package builtin.aws.backup.aws0342

test_detects_when_disabled {
	r := deny with input as {"aws": {"backup": {"plans": [{"rules": [{"lifecycle": {}}]}]}}}
	count(r) == 1
}

test_when_enabled {
	r := deny with input as {"aws": {"backup": {"plans": [{"rules": [{"lifecycle": {"deleteafterdays": {"value": 34},"movetocoldstorageafterdays": {"value": 35}}}]}]}}}
	count(r) == 0
}
