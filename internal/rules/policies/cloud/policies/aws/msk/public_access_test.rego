package builtin.aws.msk.aws0304

test_detects_when_disabled{
	r := deny with input as {"aws": {"msk": {"clusters": [{"brokernodegroupinfo": {"connectivityinfo": {"publicaccess": {"type": {"value": "DISABLED"}}}}}]}}}
	count(r) == 0
}

test_when_enabled {
	r := deny with input as {"aws": {"msk": {"clusters": [{"brokernodegroupinfo": {"connectivityinfo": {"publicaccess": {"type": {"value": "SERVICE_PROVIDED_EIPS"}}}}}]}}}
	count(r) == 1
}
