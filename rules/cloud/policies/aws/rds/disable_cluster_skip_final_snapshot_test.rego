package PACKAGE_NAME

test_when_enabled {
	r := deny with input as {"aws": {"rds": {"clusters": [{"skipfinalsnapshot": {"value": true}}]}}}
	count(r) == 1
}

test_detects_when_disabled {
	r := deny with input as {"aws": {"rds": {"clusters": [{"skipfinalsnapshot": {"value": false}}]}}}
	count(r) == 0
}
