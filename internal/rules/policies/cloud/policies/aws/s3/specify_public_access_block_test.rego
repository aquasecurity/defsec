package builtin.aws.s3.aws0218

test_detects_when_has_public_access_block{
	r := deny with input as {"aws": {"s3": {"buckets": [{"publicaccessblock": {"blockpublicacls": {"value": true}}}]}}}
	count(r) == 0
}

test_when_has_no_public_access_block {
	r := deny with input as {"aws": {"s3": {"buckets": [{}]}}}
	count(r) == 1
}

test_when_has_missing_public_access_block {
	r := deny with input as {"aws": {"s3": {"buckets": [{"publicaccessblock": {"blockpublicacls": {"value": false},
	                                                                          "blockpublicpolicy": {"value": true},
																			  "ignorepublicacls": {"value": false},
																			  "restrictpublicbuckets": {"value": false}}}]}}}
	count(r) == 1
}

test_when_has_no_missing_public_access_block {
	r := deny with input as {"aws": {"s3": {"buckets": [{"publicaccessblock": {"blockpublicacls": {"value": true},
	                                                                          "blockpublicpolicy": {"value": true},
																			  "ignorepublicacls": {"value": true},
																			  "restrictpublicbuckets": {"value": true}}}]}}}
	count(r) == 0
}
